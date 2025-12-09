#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../include/security.h"

#define MAX_COMMANDS_PER_MINUTE 60
#define SUSPICIOUS_COMMAND_THRESHOLD 10
#define MAX_FAILED_COMMANDS 5
#define SHELL_NAME "bellshell"

/* Global state */
static rate_limit_state_t g_rate_limit = {0};
static volatile sig_atomic_t g_shutdown_requested = 0;
static int g_audit_fd = -1;

/* Public function to access shutdown flag from other modules */
volatile sig_atomic_t *get_shutdown_flag(void) {
    return &g_shutdown_requested;
}

/* Check rate limit */
bool check_rate_limit(void) {
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

/* Record command execution result and detect suspicious patterns */
void record_command_result(cmd_result_t result, const char *cmd) {
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
                     "Suspicious command pattern: %s", cmd);
            syslog(LOG_NOTICE, "[SECURITY] %s (uid=%d)", audit_msg, getuid());
            break;
        }
    }
}

/* Initialize secure logging */
int init_secure_logging(void) {
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
            static char fallback_path[4096];
            snprintf(fallback_path, sizeof(fallback_path),
                     "%s/.bellshell/audit.log", home);

            char fallback_dir[4096];
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

/* Close secure logging */
void close_secure_logging(void) {
    if (g_audit_fd != -1) {
        close(g_audit_fd);
        g_audit_fd = -1;
    }
    closelog();
}

/* Audit log with timestamp and metadata */
void audit_log_secure(int priority, const char *level, const char *message) {
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

/* Signal handlers */
static void sigint_handler(int signo) {
    (void)signo;
    const char msg[] = "\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    g_shutdown_requested = 1;
}

static void sigchld_handler(int signo) {
    (void)signo;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

/* Setup signal handlers */
void setup_signal_handlers(void) {
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

/* Drop privileges permanently */
int drop_privileges_permanently(void) {
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
