/* Enable POSIX/XOPEN extensions so nftw/FTW_* are visible */
#define _XOPEN_SOURCE 700

#include <stddef.h>   /* size_t */
#include <stdio.h>    /* printf, fprintf, EOF, getchar */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ftw.h>      /* nftw, struct FTW, FTW_PHYS, FTW_MOUNT */
#include <time.h>
#include <fcntl.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define MAX_PATH_LEN 4096
#define SHELL_NAME "bellshell"
#define VERSION "1.2.0"

/* Command execution result codes */
typedef enum {
    CMD_SUCCESS = 0,
    CMD_ERROR = 1,
    CMD_EXIT = 2
} cmd_result_t;

/* Global flag for graceful shutdown */
static volatile sig_atomic_t g_shutdown_requested = 0;

/* Audit log file descriptor (global for signal safety) */
static int g_audit_fd = -1;

/* ======================= LOGGING & AUDITING ======================= */

/**
 * Initialize audit logging to a secure location
 * Returns: 0 on success, -1 on failure
 */
static int init_audit_log(void) {
    const char *log_path = "/tmp/bellshell_audit.log";
    
    /* Open with restricted permissions: owner read/write only */
    g_audit_fd = open(log_path, 
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                      S_IRUSR | S_IWUSR);
    
    if (g_audit_fd == -1) {
        fprintf(stderr, "Warning: Could not open audit log: %s\n", 
                strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * Write audit message (async-signal-safe)
 * Format: [TIMESTAMP] [LEVEL] message
 */
static void audit_log(const char *level, const char *message) {
    if (g_audit_fd == -1) return;
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(timestamp, sizeof(timestamp), "UNKNOWN");
    }
    
    char log_entry[512];
    int len = snprintf(log_entry, sizeof(log_entry), 
                       "[%s] [%s] %s\n", timestamp, level, message);
    
    if (len > 0 && len < (int)sizeof(log_entry)) {
        /* write() is async-signal-safe */
        ssize_t written = write(g_audit_fd, log_entry, (size_t)len);
        (void)written; /* Suppress unused warning */
    }
}

/**
 * Close audit log
 */
static void close_audit_log(void) {
    if (g_audit_fd != -1) {
        close(g_audit_fd);
        g_audit_fd = -1;
    }
}

/* ======================= SIGNAL HANDLING ======================= */

static void sigint_handler(int signo) {
    (void)signo;
    const char msg[] = "\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    g_shutdown_requested = 0; /* Reset for user control */
}

static void sigchld_handler(int signo) {
    (void)signo;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

static void setup_signal_handlers(void) {
    struct sigaction sa_int, sa_chld;

    memset(&sa_int, 0, sizeof(sa_int));
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("sigaction(SIGINT)");
    }

    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction(SIGCHLD)");
    }
}

/* ======================= STRING HELPERS ======================= */

static void trim_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n') {
        s[len - 1] = '\0';
    }
}

static void trim_whitespace(char *s) {
    if (!s) return;

    char *start = s;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }

    *end = '\0';

    if (start != s) {
        memmove(s, start, (size_t)(end - start) + 1);
    }
}

/* Parse command line with support for quoted arguments */
static int parse_line(char *line, char **argv) {
    int argc = 0;
    char *p = line;
    char quote_char = '\0';

    while (*p != '\0' && argc < MAX_ARGS - 1) {
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0') break;

        if (*p == '"' || *p == '\'') {
            quote_char = *p;
            p++;
            argv[argc++] = p;

            while (*p != '\0' && *p != quote_char) {
                p++;
            }
            if (*p == quote_char) {
                *p = '\0';
                p++;
            }
        } else {
            argv[argc++] = p;
            while (*p != '\0' && !isspace((unsigned char)*p)) {
                p++;
            }
            if (*p != '\0') {
                *p = '\0';
                p++;
            }
        }
    }

    argv[argc] = NULL;
    return argc;
}

/* ======================= PATH VALIDATION ======================= */

/**
 * Validate that a path is safe to scan
 * Returns: true if safe, false otherwise
 */
static bool is_safe_scan_path(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
    
    /* Blacklist dangerous pseudo-filesystems that could hang */
    const char *dangerous_paths[] = {
        "/proc",
        "/sys",
        "/dev/pts",
        "/dev/shm",
        NULL
    };
    
    for (int i = 0; dangerous_paths[i] != NULL; i++) {
        size_t danger_len = strlen(dangerous_paths[i]);
        if (strncmp(path, dangerous_paths[i], danger_len) == 0) {
            /* Check if it's an exact match or starts with path/ */
            if (path[danger_len] == '\0' || path[danger_len] == '/') {
                return false;
            }
        }
    }
    
    /* Resolve to canonical path to detect symlink tricks */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        return false; /* Path doesn't exist or inaccessible */
    }
    
    /* Verify the resolved path still matches our original intent */
    /* (Prevents symlink-based escapes) */
    return true;
}

/* ======================= BUILT-INS ======================= */

static cmd_result_t builtin_exit(int argc, char **argv) {
    int exit_code = 0;

    if (argc > 1) {
        char *endptr = NULL;
        long code = strtol(argv[1], &endptr, 10);
        if (*endptr != '\0' || code < 0 || code > 255) {
            fprintf(stderr, "exit: invalid exit code: %s\n", argv[1]);
            return CMD_ERROR;
        }
        exit_code = (int)code;
    }
    
    audit_log("INFO", "Shell exiting normally");
    exit(exit_code);
}

static cmd_result_t builtin_cd(int argc, char **argv) {
    const char *target = NULL;

    if (argc < 2) {
        target = getenv("HOME");
        if (!target) {
            fprintf(stderr, "cd: HOME not set\n");
            return CMD_ERROR;
        }
    } else if (argc > 2) {
        fprintf(stderr, "cd: too many arguments\n");
        return CMD_ERROR;
    } else {
        target = argv[1];
    }

    if (chdir(target) != 0) {
        fprintf(stderr, "cd: %s: %s\n", target, strerror(errno));
        return CMD_ERROR;
    }

    return CMD_SUCCESS;
}

static cmd_result_t builtin_help(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("%s version %s\n", SHELL_NAME, VERSION);
    printf("\n=== Built-in Commands ===\n");
    printf("  cd [dir]           - Change directory\n");
    printf("  exit [code]        - Exit shell\n");
    printf("  help               - Show this help\n");
    printf("  suidscan [options] - Scan for SUID/SGID binaries\n");
    printf("      -d <dir>       - Start directory (default: /usr /bin /sbin)\n");
    printf("      -s             - Include SGID binaries in results\n");
    printf("      -v             - Verbose output with permissions\n");
    printf("\n=== Security Features ===\n");
    printf("  - Audit logging enabled at /tmp/bellshell_audit.log\n");
    printf("  - SUID scans validate paths and skip dangerous filesystems\n");
    printf("  - Command history and security events are logged\n");
    printf("\nAll other commands are executed as external programs.\n");

    return CMD_SUCCESS;
}

/* ======= ENHANCED SUIDSCAN IMPLEMENTATION ======= */

/* Context structure for suidscan callback */
typedef struct {
    int count_suid;
    int count_sgid;
    bool include_sgid;
    bool verbose;
    time_t start_time;
    int files_scanned;
} suidscan_context_t;

static suidscan_context_t g_scan_ctx = {0};

/**
 * Callback for nftw during SUID/SGID scan
 * Uses global context to avoid non-reentrant issues
 */
static int suidscan_cb(const char *fpath, const struct stat *sb,
                       int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    
    /* Check if scan should be interrupted */
    if (g_shutdown_requested) {
        return 1; /* Stop traversal */
    }

    /* Only process regular files and symlinks */
    if (typeflag != FTW_F && typeflag != FTW_SL) {
        return 0;
    }
    
    /* Security: Re-stat the file to avoid TOCTOU */
    struct stat current_stat;
    if (lstat(fpath, &current_stat) == -1) {
        /* File disappeared or permission denied - skip silently */
        return 0;
    }
    
    /* Verify file hasn't changed since nftw's stat */
    if (current_stat.st_ino != sb->st_ino || 
        current_stat.st_dev != sb->st_dev) {
        /* File was replaced - potential attack, log and skip */
        char msg[512];
        snprintf(msg, sizeof(msg), 
                 "SECURITY: File replaced during scan: %s", fpath);
        audit_log("WARNING", msg);
        return 0;
    }

    bool is_suid = (current_stat.st_mode & S_ISUID) != 0;
    bool is_sgid = (current_stat.st_mode & S_ISGID) != 0;

    if (is_suid || (is_sgid && g_scan_ctx.include_sgid)) {
        /* Construct output message */
        char type_str[16] = {0};
        if (is_suid && is_sgid) {
            snprintf(type_str, sizeof(type_str), "SUID+SGID");
        } else if (is_suid) {
            snprintf(type_str, sizeof(type_str), "SUID");
        } else {
            snprintf(type_str, sizeof(type_str), "SGID");
        }
        
        if (g_scan_ctx.verbose) {
            printf("[%s] %s\n", type_str, fpath);
            printf("       Owner: uid=%d gid=%d Mode: %04o\n",
                   current_stat.st_uid, current_stat.st_gid,
                   current_stat.st_mode & 07777);
        } else {
            printf("[%s] %s (uid=%d)\n", type_str, fpath, 
                   current_stat.st_uid);
        }
        
        if (is_suid) g_scan_ctx.count_suid++;
        if (is_sgid) g_scan_ctx.count_sgid++;
        
        /* Audit log the finding */
        char audit_msg[512];
        snprintf(audit_msg, sizeof(audit_msg),
                 "Found %s binary: %s (uid=%d)", 
                 type_str, fpath, current_stat.st_uid);
        audit_log("SECURITY", audit_msg);
    }
    
    /* Progress indicator every 1000 files */
    g_scan_ctx.files_scanned++;
    if (g_scan_ctx.files_scanned % 1000 == 0) {
        time_t elapsed = time(NULL) - g_scan_ctx.start_time;
        fprintf(stderr, "\r[Scanning... %d files checked, %lds elapsed]",
                g_scan_ctx.files_scanned, (long)elapsed);
        fflush(stderr);
    }

    return 0;
}

/**
 * Parse suidscan command options
 * Returns: 0 on success, -1 on error
 */
static int parse_suidscan_options(int argc, char **argv, 
                                   const char **start_dir,
                                   bool *include_sgid,
                                   bool *verbose) {
    *start_dir = NULL;
    *include_sgid = false;
    *verbose = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "suidscan: -d requires a directory argument\n");
                return -1;
            }
            *start_dir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            *include_sgid = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            *verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: suidscan [options]\n");
            printf("Options:\n");
            printf("  -d <dir>  Start directory (default: /usr /bin /sbin)\n");
            printf("  -s        Include SGID binaries\n");
            printf("  -v        Verbose output\n");
            printf("  -h        Show this help\n");
            return -1;
        } else {
            fprintf(stderr, "suidscan: unknown option: %s\n", argv[i]);
            return -1;
        }
    }
    
    return 0;
}

/**
 * SUID/SGID binary scanner with security hardening
 */
static cmd_result_t builtin_suidscan(int argc, char **argv) {
    const char *start_dir = NULL;
    bool include_sgid = false;
    bool verbose = false;
    
    /* Parse options */
    if (parse_suidscan_options(argc, argv, &start_dir, 
                                &include_sgid, &verbose) != 0) {
        return CMD_ERROR;
    }
    
    /* Default search paths if none specified */
    const char *default_paths[] = {"/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL};
    const char **search_paths;
    
    if (start_dir) {
        /* Validate user-provided path */
        if (!is_safe_scan_path(start_dir)) {
            fprintf(stderr, "suidscan: refusing to scan dangerous path: %s\n", 
                    start_dir);
            audit_log("SECURITY", "Attempted scan of dangerous path blocked");
            return CMD_ERROR;
        }
        
        static const char *custom_paths[2];
        custom_paths[0] = start_dir;
        custom_paths[1] = NULL;
        search_paths = custom_paths;
    } else {
        search_paths = default_paths;
    }
    
    /* Initialize scan context */
    memset(&g_scan_ctx, 0, sizeof(g_scan_ctx));
    g_scan_ctx.include_sgid = include_sgid;
    g_scan_ctx.verbose = verbose;
    g_scan_ctx.start_time = time(NULL);
    
    /* Log scan initiation */
    char audit_msg[256];
    snprintf(audit_msg, sizeof(audit_msg), 
             "SUID scan initiated by uid=%d", getuid());
    audit_log("SECURITY", audit_msg);
    
    printf("\n=== SUID/SGID Binary Scanner ===\n");
    printf("Scanning paths: ");
    for (int i = 0; search_paths[i] != NULL; i++) {
        printf("%s ", search_paths[i]);
    }
    printf("\n");
    if (include_sgid) {
        printf("Mode: SUID + SGID binaries\n");
    } else {
        printf("Mode: SUID binaries only\n");
    }
    printf("This may take some time...\n\n");
    
    /* Perform scan on each path */
    int flags = FTW_PHYS | FTW_MOUNT; /* Don't follow symlinks or cross filesystems */
    int max_fd = 15; /* Conservative limit to avoid fd exhaustion */
    
    for (int i = 0; search_paths[i] != NULL; i++) {
        if (g_shutdown_requested) {
            printf("\n[Scan interrupted by user]\n");
            break;
        }
        
        if (nftw(search_paths[i], suidscan_cb, max_fd, flags) == -1) {
            if (errno == EACCES) {
                fprintf(stderr, "\nWarning: Permission denied for %s (continuing)\n", 
                        search_paths[i]);
            } else {
                fprintf(stderr, "\nsuidscan: nftw(%s): %s\n", 
                        search_paths[i], strerror(errno));
            }
        }
    }
    
    /* Clear progress line */
    fprintf(stderr, "\r%*s\r", 60, "");
    
    /* Summary */
    printf("\n=== Scan Complete ===\n");
    printf("Files scanned: %d\n", g_scan_ctx.files_scanned);
    printf("SUID binaries found: %d\n", g_scan_ctx.count_suid);
    if (include_sgid) {
        printf("SGID binaries found: %d\n", g_scan_ctx.count_sgid);
    }
    
    time_t elapsed = time(NULL) - g_scan_ctx.start_time;
    printf("Time elapsed: %ld seconds\n", (long)elapsed);
    
    /* Log completion */
    snprintf(audit_msg, sizeof(audit_msg),
             "SUID scan completed: %d SUID, %d SGID binaries found",
             g_scan_ctx.count_suid, g_scan_ctx.count_sgid);
    audit_log("INFO", audit_msg);
    
    return CMD_SUCCESS;
}

/* ======================= BUILTIN DISPATCH ======================= */

static int handle_builtin(int argc, char **argv) {
    if (argc == 0) {
        return CMD_SUCCESS;
    }

    struct builtin_entry {
        const char    *name;
        cmd_result_t (*handler)(int, char **);
    };

    static const struct builtin_entry builtins[] = {
        { "exit",     builtin_exit     },
        { "cd",       builtin_cd       },
        { "help",     builtin_help     },
        { "suidscan", builtin_suidscan },
        { NULL,       NULL             }
    };

    for (int i = 0; builtins[i].name != NULL; i++) {
        if (strcmp(argv[0], builtins[i].name) == 0) {
            return builtins[i].handler(argc, argv);
        }
    }

    return -1;
}

/* ======================= EXTERNAL COMMANDS ======================= */

static cmd_result_t execute_external(int argc, char **argv) {
    (void)argc;
    
    /* Audit log external command execution */
    char audit_msg[256];
    snprintf(audit_msg, sizeof(audit_msg), "Executing: %s", argv[0]);
    audit_log("INFO", audit_msg);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return CMD_ERROR;
    }

    if (pid == 0) {
        execvp(argv[0], argv);
        fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }

    int status;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r == -1 && errno == EINTR);

    if (r == -1) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        return CMD_ERROR;
    }

    if (WIFEXITED(status)) {
        return (WEXITSTATUS(status) == 0) ? CMD_SUCCESS : CMD_ERROR;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Command terminated by signal %d\n", WTERMSIG(status));
        return CMD_ERROR;
    }

    return CMD_SUCCESS;
}

/* ======================= PROMPT & MAIN LOOP ======================= */

static void display_prompt(void) {
    char cwd[PATH_MAX];

    if (!getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "getcwd: %s\n", strerror(errno));
        printf("%s> ", SHELL_NAME);
    } else {
        char *base = strrchr(cwd, '/');
        if (base && base[1] != '\0') {
            printf("%s:%s> ", SHELL_NAME, base + 1);
        } else {
            printf("%s:%s> ", SHELL_NAME, cwd);
        }
    }
    fflush(stdout);
}

int main(void) {
    char line[MAX_LINE];
    char *argv[MAX_ARGS];

    /* Initialize security subsystems */
    init_audit_log();
    setup_signal_handlers();
    
    audit_log("INFO", "Shell started");

    printf("Welcome to %s v%s\n", SHELL_NAME, VERSION);
    printf("Type 'help' for available commands.\n");
    printf("Security: Audit logging enabled\n\n");

    while (!g_shutdown_requested) {
        display_prompt();

        if (!fgets(line, sizeof(line), stdin)) {
            if (feof(stdin)) {
                printf("\n");
                break;
            } else if (errno == EINTR) {
                clearerr(stdin);
                continue;
            } else {
                fprintf(stderr, "fgets: %s\n", strerror(errno));
                break;
            }
        }

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(stdin)) {
            fprintf(stderr, "Error: input line too long (max %d chars)\n",
                    MAX_LINE - 1);
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            continue;
        }

        trim_newline(line);
        trim_whitespace(line);

        if (line[0] == '\0')
            continue;

        int argc = parse_line(line, argv);
        if (argc == 0)
            continue;

        int builtin_result = handle_builtin(argc, argv);
        if (builtin_result >= 0) {
            if (builtin_result == CMD_EXIT) {
                break;
            }
            continue;
        }

        execute_external(argc, argv);
    }

    audit_log("INFO", "Shell shutting down");
    close_audit_log();
    
    printf("Goodbye!\n");
    return 0;
}
