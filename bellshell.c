#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <ftw.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <arpa/inet.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define MAX_PATH_LEN 4096
#define SHELL_NAME "bellshell"
#define VERSION "2.0.0-secure"

/* Security: Rate limiting constants */
#define MAX_COMMANDS_PER_MINUTE 60
#define SUSPICIOUS_COMMAND_THRESHOLD 10
#define MAX_FAILED_COMMANDS 5

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

/* ======================= RATE LIMITING & ANOMALY DETECTION ======================= */

typedef struct {
    time_t window_start;
    int command_count;
    int failed_commands;
    int suspicious_commands;
    time_t last_suidscan;
} rate_limit_state_t;

static rate_limit_state_t g_rate_limit = {0};

static bool check_rate_limit(void) {
    time_t now = time(NULL);
    
    /* Reset counter every minute */
    if (now - g_rate_limit.window_start >= 60) {
        g_rate_limit.window_start = now;
        g_rate_limit.command_count = 0;
        g_rate_limit.failed_commands = 0;
        g_rate_limit.suspicious_commands = 0;
    }
    
    g_rate_limit.command_count++;
    
    /* Check for rate limit violation */
    if (g_rate_limit.command_count > MAX_COMMANDS_PER_MINUTE) {
        fprintf(stderr, "Rate limit exceeded (%d commands/min). Please slow down.\n",
                MAX_COMMANDS_PER_MINUTE);
        syslog(LOG_WARNING, "Rate limit exceeded by uid=%d - possible automation", 
               getuid());
        sleep(1); /* Throttle attacker */
        return false;
    }
    
    /* Check for suspicious patterns */
    if (g_rate_limit.failed_commands > MAX_FAILED_COMMANDS) {
        syslog(LOG_ALERT, "Multiple failed commands (uid=%d) - possible probing", 
               getuid());
    }
    
    if (g_rate_limit.suspicious_commands > SUSPICIOUS_COMMAND_THRESHOLD) {
        fprintf(stderr, "WARNING: Suspicious activity detected. All actions are logged.\n");
        syslog(LOG_CRIT, "Anomalous command pattern detected (uid=%d)", getuid());
    }
    
    return true;
}

static void record_command_result(cmd_result_t result, const char *cmd) {
    if (result != CMD_SUCCESS) {
        g_rate_limit.failed_commands++;
    }
    
    /* Detect suspicious commands */
    const char *suspicious_patterns[] = {
        "passwd", "shadow", "sudoers", "sudo", "su",
        "chmod", "chown", "setuid", "setgid",
        "nc", "netcat", "telnet", "nmap",
        "/etc/passwd", "/etc/shadow", 
        "rm -rf", "dd if=", "mkfs",
        NULL
    };
    
    for (int i = 0; suspicious_patterns[i] != NULL; i++) {
        if (strstr(cmd, suspicious_patterns[i]) != NULL) {
            g_rate_limit.suspicious_commands++;
            
            char audit_msg[512];
            snprintf(audit_msg, sizeof(audit_msg),
             "SUID scan completed: %d SUID, %d SGID binaries found",
             g_scan_ctx.count_suid, g_scan_ctx.count_sgid);
    audit_log_secure(LOG_INFO, "INFO", audit_msg);

    return CMD_SUCCESS;
}

/* Privilege-separated SUID scanner */
static cmd_result_t builtin_suidscan(int argc, char **argv) {
    /* Rate limit SUID scans to prevent abuse */
    time_t now = time(NULL);
    if (now - g_rate_limit.last_suidscan < 300) { /* 5 minutes */
        time_t wait_time = 300 - (now - g_rate_limit.last_suidscan);
        fprintf(stderr, "suidscan: Rate limited. Wait %ld seconds before next scan.\n",
                (long)wait_time);
        return CMD_ERROR;
    }
    
    /* Require explicit confirmation */
    printf("WARNING: SUID scanning is a security-sensitive operation.\n");
    printf("This scan will be logged. Continue? (yes/no): ");
    fflush(stdout);
    
    char response[16];
    if (!fgets(response, sizeof(response), stdin)) {
        return CMD_ERROR;
    }
    
    trim_newline(response);
    trim_whitespace(response);
    
    if (strcmp(response, "yes") != 0) {
        printf("Scan cancelled.\n");
        return CMD_SUCCESS;
    }
    
    g_rate_limit.last_suidscan = now;
    
    /* Fork and drop privileges */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return CMD_ERROR;
    }
    
    if (pid == 0) {
        /* Child: drop privileges and scan */
        if (drop_privileges_permanently() != 0) {
            fprintf(stderr, "Failed to drop privileges\n");
            exit(EXIT_FAILURE);
        }
        
        exit(builtin_suidscan_impl(argc, argv));
    }
    
    /* Parent: wait for scan */
    int status;
    waitpid(pid, &status, 0);
    
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 
           ? CMD_SUCCESS : CMD_ERROR;
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
        { "allowed",  builtin_allowed  },
        { NULL,       NULL             }
    };

    for (int i = 0; builtins[i].name != NULL; i++) {
        if (strcmp(argv[0], builtins[i].name) == 0) {
            return builtins[i].handler(argc, argv);
        }
    }

    return -1;
}

/* ======================= EXTERNAL COMMAND EXECUTION ======================= */

static cmd_result_t execute_external_secure(int argc, char **argv) {
    (void)argc;
    
    /* Validate command is in whitelist */
    if (!is_command_allowed(argv[0])) {
        fprintf(stderr, "Command not allowed: %s\n", argv[0]);
        fprintf(stderr, "Type 'allowed' to see whitelisted commands.\n");
        
        char audit_msg[512];
        snprintf(audit_msg, sizeof(audit_msg), 
                 "Blocked unauthorized command: %s", argv[0]);
        audit_log_secure(LOG_WARNING, "SECURITY", audit_msg);
        
        return CMD_ERROR;
    }

    /* Log command execution */
    char cmd_str[512] = {0};
    size_t offset = 0;
    for (int i = 0; argv[i] && offset < sizeof(cmd_str) - 1; i++) {
        int written = snprintf(cmd_str + offset, sizeof(cmd_str) - offset,
                              "%s%s", i > 0 ? " " : "", argv[i]);
        if (written > 0) offset += (size_t)written;
    }
    
    char audit_msg[512];
    snprintf(audit_msg, sizeof(audit_msg), "Executing: %s", cmd_str);
    audit_log_secure(LOG_INFO, "INFO", audit_msg);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return CMD_ERROR;
    }

    if (pid == 0) {
        /* Child process */
        execvp(argv[0], argv);
        fprintf(stderr, "%s: %s\n", argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Parent: wait for command */
    int status;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r == -1 && errno == EINTR);

    if (r == -1) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        return CMD_ERROR;
    }

    cmd_result_t result;
    if (WIFEXITED(status)) {
        result = (WEXITSTATUS(status) == 0) ? CMD_SUCCESS : CMD_ERROR;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Command terminated by signal %d\n", WTERMSIG(status));
        result = CMD_ERROR;
    } else {
        result = CMD_ERROR;
    }
    
    return result;
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
    init_secure_logging();
    setup_signal_handlers();
    
    audit_log_secure(LOG_INFO, "INFO", "Shell started");

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  %s v%s - Hardened Shell                    ║\n", SHELL_NAME, VERSION);
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Security Features:\n");
    printf("  ✓ Audit logging enabled (syslog + file)\n");
    printf("  ✓ Command whitelisting active\n");
    printf("  ✓ Input sanitization enabled\n");
    printf("  ✓ Rate limiting: %d commands/min\n", MAX_COMMANDS_PER_MINUTE);
    printf("  ✓ Anomaly detection active\n");
    printf("\n");
    printf("Type 'help' for available commands.\n");
    printf("Type 'allowed' to see whitelisted external commands.\n\n");

    while (!g_shutdown_requested) {
        display_prompt();

        /* Check rate limit before accepting input */
        if (!check_rate_limit()) {
            continue;
        }

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
            
            audit_log_secure(LOG_WARNING, "SECURITY", 
                           "Oversized input detected - possible buffer overflow attempt");
            
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            continue;
        }

        trim_newline(line);
        trim_whitespace(line);

        if (line[0] == '\0')
            continue;

        int argc = parse_line_secure(line, argv);
        if (argc == 0) {
            /* parse_line_secure already logged the issue */
            record_command_result(CMD_ERROR, line);
            continue;
        }

        /* Handle built-in commands */
        int builtin_result = handle_builtin(argc, argv);
        if (builtin_result >= 0) {
            if (builtin_result == CMD_EXIT) {
                break;
            }
            record_command_result(builtin_result, argv[0]);
            continue;
        }

        /* Execute external command */
        cmd_result_t result = execute_external_secure(argc, argv);
        record_command_result(result, argv[0]);
    }

    audit_log_secure(LOG_INFO, "INFO", "Shell shutting down");
    close_secure_logging();

    printf("\nGoodbye!\n");
    return 0;
}        "Suspicious command pattern: %s", cmd);
            syslog(LOG_NOTICE, "[SECURITY] %s (uid=%d)", audit_msg, getuid());
            break;
        }
    }
}

/* ======================= SECURE LOGGING & AUDITING ======================= */

static int init_secure_logging(void) {
    /* Open connection to system logger */
    openlog(SHELL_NAME, LOG_PID | LOG_CONS, LOG_AUTHPRIV);
    
    /* Create secure log directory */
    const char *log_dir = "/var/log/bellshell";
    const char *log_path = "/var/log/bellshell/audit.log";
    
    /* Try to create directory with restricted permissions */
    if (mkdir(log_dir, S_IRWXU) != 0 && errno != EEXIST) {
        /* Fall back to user's home if /var/log is not writable */
        const char *home = getenv("HOME");
        if (home) {
            static char fallback_path[PATH_MAX];
            snprintf(fallback_path, sizeof(fallback_path), 
                     "%s/.bellshell/audit.log", home);
            
            char fallback_dir[PATH_MAX];
            snprintf(fallback_dir, sizeof(fallback_dir), "%s/.bellshell", home);
            mkdir(fallback_dir, S_IRWXU);
            
            log_path = fallback_path;
        } else {
            log_path = "/tmp/bellshell_audit.log";
        }
    }
    
    /* Open with restricted permissions and safety flags */
    g_audit_fd = open(log_path,
                      O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW,
                      S_IRUSR | S_IWUSR);
    
    if (g_audit_fd == -1) {
        syslog(LOG_ERR, "Failed to open audit log at %s: %s", 
               log_path, strerror(errno));
        return -1;
    }
    
    /* Verify file ownership to prevent symlink attacks */
    struct stat st;
    if (fstat(g_audit_fd, &st) == 0) {
        if (st.st_uid != getuid()) {
            syslog(LOG_CRIT, "Audit log has wrong owner - potential tampering detected");
            close(g_audit_fd);
            g_audit_fd = -1;
            return -1;
        }
    }
    
    syslog(LOG_INFO, "Audit logging initialized at %s", log_path);
    return 0;
}

static void audit_log_secure(int priority, const char *level, const char *message) {
    /* Always log to syslog for tamper-proof logging */
    syslog(priority, "[%s] %s", level, message);
    
    /* Also log to file if available */
    if (g_audit_fd == -1) return;
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(timestamp, sizeof(timestamp), "UNKNOWN");
    }
    
    char log_entry[1024];
    int len = snprintf(log_entry, sizeof(log_entry),
                       "[%s] [PID:%d] [UID:%d] [%s] %s\n", 
                       timestamp, getpid(), getuid(), level, message);
    
    if (len > 0 && len < (int)sizeof(log_entry)) {
        ssize_t written = write(g_audit_fd, log_entry, (size_t)len);
        if (written == -1) {
            syslog(LOG_ERR, "Failed to write audit log: %s", strerror(errno));
        }
    }
}

static void close_secure_logging(void) {
    if (g_audit_fd != -1) {
        close(g_audit_fd);
        g_audit_fd = -1;
    }
    closelog();
}

/* ======================= SIGNAL HANDLING ======================= */

static void sigint_handler(int signo) {
    (void)signo;
    const char msg[] = "\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    g_shutdown_requested = 0;
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

/* ======================= INPUT SANITIZATION & VALIDATION ======================= */

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

/* Validate that argument doesn't contain shell metacharacters */
static bool is_safe_argument(const char *arg) {
    if (!arg) return false;
    
    /* Reject dangerous shell metacharacters */
    const char *dangerous = "|&;<>()$`\\\"'*?[]!{}~";
    
    for (const char *p = arg; *p; p++) {
        if (strchr(dangerous, *p) != NULL) {
            return false;
        }
    }
    
    /* Reject null bytes */
    if (strlen(arg) != (size_t)(strchr(arg, '\0') - arg)) {
        return false;
    }
    
    return true;
}

/* Sanitize path to prevent directory traversal */
static bool sanitize_path(const char *path, char *sanitized, size_t size) {
    if (!path || !sanitized || size == 0) return false;
    
    /* Resolve to absolute path */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        /* If path doesn't exist, check parent directory */
        char parent[PATH_MAX];
        char *last_slash = strrchr(path, '/');
        
        if (last_slash) {
            size_t parent_len = (size_t)(last_slash - path);
            if (parent_len == 0) parent_len = 1; /* root */
            strncpy(parent, path, parent_len);
            parent[parent_len] = '\0';
            
            if (!realpath(parent, resolved)) {
                return false;
            }
        } else {
            if (!getcwd(resolved, sizeof(resolved))) {
                return false;
            }
        }
    }
    
    /* Check for directory traversal attempts */
    if (strstr(resolved, "..") != NULL) {
        return false;
    }
    
    strncpy(sanitized, resolved, size - 1);
    sanitized[size - 1] = '\0';
    return true;
}

/* Parse command line with security validation */
static int parse_line_secure(char *line, char **argv) {
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
    
    /* Validate each argument */
    for (int i = 0; i < argc; i++) {
        if (!is_safe_argument(argv[i])) {
            fprintf(stderr, "Security: Dangerous characters detected in argument: %s\n", 
                    argv[i]);
            audit_log_secure(LOG_WARNING, "SECURITY", 
                           "Command injection attempt blocked");
            return 0;
        }
    }
    
    return argc;
}

/* ======================= PATH VALIDATION ======================= */

static bool is_safe_scan_path(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }

    /* Blacklist dangerous pseudo-filesystems */
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
            if (path[danger_len] == '\0' || path[danger_len] == '/') {
                return false;
            }
        }
    }

    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) {
        return false;
    }

    return true;
}

/* ======================= PRIVILEGE SEPARATION ======================= */

static int drop_privileges_permanently(void) {
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    
    /* Drop supplementary groups */
    if (setgroups(0, NULL) != 0) {
        perror("setgroups");
        return -1;
    }
    
    /* Drop to real GID */
    if (setgid(real_gid) != 0) {
        perror("setgid");
        return -1;
    }
    
    /* Drop to real UID (irreversible) */
    if (setuid(real_uid) != 0) {
        perror("setuid");
        return -1;
    }
    
    /* Verify we can't regain privileges */
    if (setuid(0) == 0) {
        fprintf(stderr, "SECURITY ERROR: Failed to drop privileges permanently\n");
        syslog(LOG_CRIT, "Privilege drop validation failed - possible security breach");
        return -1;
    }
    
    return 0;
}

/* ======================= COMMAND WHITELISTING ======================= */

/* List of allowed external commands */
static const char *allowed_commands[] = {
    "ls", "cat", "grep", "find", "ps", "top", "htop",
    "df", "du", "pwd", "whoami", "id", "date", "uptime",
    "echo", "head", "tail", "wc", "sort", "uniq",
    "less", "more", "file", "stat", "which", "whereis",
    "uname", "hostname", "free", "vmstat", "iostat",
    NULL
};

static bool is_command_allowed(const char *cmd) {
    if (!cmd) return false;
    
    /* Extract basename if full path provided */
    const char *basename = strrchr(cmd, '/');
    if (basename) {
        basename++;
    } else {
        basename = cmd;
    }
    
    /* Check if command is in allowlist */
    for (int i = 0; allowed_commands[i] != NULL; i++) {
        if (strcmp(basename, allowed_commands[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

/* ======================= BUILT-IN COMMANDS ======================= */

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

    audit_log_secure(LOG_INFO, "INFO", "Shell exiting normally");
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
    
    /* Sanitize path */
    char safe_path[PATH_MAX];
    if (!sanitize_path(target, safe_path, sizeof(safe_path))) {
        fprintf(stderr, "cd: invalid or unsafe path: %s\n", target);
        return CMD_ERROR;
    }

    if (chdir(safe_path) != 0) {
        fprintf(stderr, "cd: %s: %s\n", safe_path, strerror(errno));
        return CMD_ERROR;
    }

    return CMD_SUCCESS;
}

static cmd_result_t builtin_help(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("\n%s version %s - Hardened Shell\n", SHELL_NAME, VERSION);
    printf("=".repeat(50) + "\n\n");
    
    printf("=== Built-in Commands ===\n");
    printf("  cd [dir]           - Change directory\n");
    printf("  exit [code]        - Exit shell\n");
    printf("  help               - Show this help\n");
    printf("  suidscan [options] - Scan for SUID/SGID binaries\n");
    printf("      -d <dir>       - Start directory (default: /usr /bin /sbin)\n");
    printf("      -s             - Include SGID binaries in results\n");
    printf("      -v             - Verbose output with permissions\n");
    printf("  allowed            - List whitelisted external commands\n");
    
    printf("\n=== Security Features ===\n");
    printf("  ✓ Audit logging (syslog + file)\n");
    printf("  ✓ Command whitelisting (only safe commands allowed)\n");
    printf("  ✓ Input sanitization (injection prevention)\n");
    printf("  ✓ Rate limiting (%d commands/minute max)\n", MAX_COMMANDS_PER_MINUTE);
    printf("  ✓ Anomaly detection (suspicious pattern recognition)\n");
    printf("  ✓ Path validation (directory traversal prevention)\n");
    printf("  ✓ Privilege separation (SUID scans run unprivileged)\n");
    
    printf("\n=== Usage Notes ===\n");
    printf("  - Only whitelisted external commands are allowed\n");
    printf("  - All commands are logged for audit purposes\n");
    printf("  - Suspicious activity triggers security alerts\n");
    printf("  - Type 'allowed' to see which external commands can run\n");
    
    printf("\n");
    return CMD_SUCCESS;
}

static cmd_result_t builtin_allowed(int argc, char **argv) {
    (void)argc;
    (void)argv;
    
    printf("\n=== Whitelisted External Commands ===\n");
    printf("The following commands are allowed to execute:\n\n");
    
    int count = 0;
    for (int i = 0; allowed_commands[i] != NULL; i++) {
        printf("  %-15s", allowed_commands[i]);
        count++;
        if (count % 4 == 0) printf("\n");
    }
    if (count % 4 != 0) printf("\n");
    
    printf("\nTotal: %d commands\n", count);
    printf("\nTo request additional commands, contact your administrator.\n\n");
    
    return CMD_SUCCESS;
}

/* ======= ENHANCED SUIDSCAN IMPLEMENTATION ======= */

typedef struct {
    int count_suid;
    int count_sgid;
    bool include_sgid;
    bool verbose;
    time_t start_time;
    int files_scanned;
} suidscan_context_t;

static suidscan_context_t g_scan_ctx = {0};

static int suidscan_cb(const char *fpath, const struct stat *sb,
                       int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;

    if (g_shutdown_requested) {
        return 1;
    }

    if (typeflag != FTW_F && typeflag != FTW_SL) {
        return 0;
    }

    /* Security: Re-stat to prevent TOCTOU attacks */
    struct stat current_stat;
    if (lstat(fpath, &current_stat) == -1) {
        return 0;
    }

    if (current_stat.st_ino != sb->st_ino ||
        current_stat.st_dev != sb->st_dev) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "File replaced during scan: %s", fpath);
        audit_log_secure(LOG_WARNING, "SECURITY", msg);
        return 0;
    }

    bool is_suid = (current_stat.st_mode & S_ISUID) != 0;
    bool is_sgid = (current_stat.st_mode & S_ISGID) != 0;

    if (is_suid || (is_sgid && g_scan_ctx.include_sgid)) {
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

        char audit_msg[512];
        snprintf(audit_msg, sizeof(audit_msg),
                 "Found %s binary: %s (uid=%d)",
                 type_str, fpath, current_stat.st_uid);
        audit_log_secure(LOG_INFO, "SECURITY", audit_msg);
    }

    g_scan_ctx.files_scanned++;
    if (g_scan_ctx.files_scanned % 1000 == 0) {
        time_t elapsed = time(NULL) - g_scan_ctx.start_time;
        fprintf(stderr, "\r[Scanning... %d files checked, %lds elapsed]",
                g_scan_ctx.files_scanned, (long)elapsed);
        fflush(stderr);
    }

    return 0;
}

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
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
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

static cmd_result_t builtin_suidscan_impl(int argc, char **argv) {
    const char *start_dir = NULL;
    bool include_sgid = false;
    bool verbose = false;

    if (parse_suidscan_options(argc, argv, &start_dir,
                               &include_sgid, &verbose) != 0) {
        return CMD_ERROR;
    }

    const char *default_paths[] = {
        "/usr/bin", "/usr/sbin", "/bin", "/sbin", NULL
    };
    const char **search_paths;

    if (start_dir) {
        if (!is_safe_scan_path(start_dir)) {
            fprintf(stderr,
                    "suidscan: refusing to scan dangerous path: %s\n",
                    start_dir);
            audit_log_secure(LOG_WARNING, "SECURITY",
                      "Attempted scan of dangerous path blocked");
            return CMD_ERROR;
        }

        static const char *custom_paths[2];
        custom_paths[0] = start_dir;
        custom_paths[1] = NULL;
        search_paths = custom_paths;
    } else {
        search_paths = default_paths;
    }

    memset(&g_scan_ctx, 0, sizeof(g_scan_ctx));
    g_scan_ctx.include_sgid = include_sgid;
    g_scan_ctx.verbose = verbose;
    g_scan_ctx.start_time = time(NULL);

    char audit_msg[256];
    snprintf(audit_msg, sizeof(audit_msg),
             "SUID scan initiated by uid=%d", getuid());
    audit_log_secure(LOG_NOTICE, "SECURITY", audit_msg);

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

    int flags = FTW_PHYS | FTW_MOUNT;
    int max_fd = 15;

    for (int i = 0; search_paths[i] != NULL; i++) {
        if (g_shutdown_requested) {
            printf("\n[Scan interrupted by user]\n");
            break;
        }

        if (nftw(search_paths[i], suidscan_cb, max_fd, flags) == -1) {
            if (errno == EACCES) {
                fprintf(stderr,
                        "\nWarning: Permission denied for %s (continuing)\n",
                        search_paths[i]);
            } else {
                fprintf(stderr,
                        "\nsuidscan: nftw(%s): %s\n",
                        search_paths[i], strerror(errno));
            }
        }
    }

    fprintf(stderr, "\r%*s\r", 60, "");

    printf("\n=== Scan Complete ===\n");
    printf("Files scanned: %d\n", g_scan_ctx.files_scanned);
    printf("SUID binaries found: %d\n", g_scan_ctx.count_suid);
    if (include_sgid) {
        printf("SGID binaries found: %d\n", g_scan_ctx.count_sgid);
    }

    time_t elapsed = time(NULL) - g_scan_ctx.start_time;
    printf("Time elapsed: %ld seconds\n", (long)elapsed);

    snprintf(audit_msg, sizeof(audit_msg),
             "
