#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/commands.h"
#include "../include/security.h"
#include "../include/suidscan.h"
#include "../include/utils.h"

/* List of allowed external commands */
static const char *allowed_commands[] = {
    "ls", "cat", "grep", "find", "ps", "top", "htop",
    "df", "du", "pwd", "whoami", "id", "date", "uptime",
    "echo", "head", "tail", "wc", "sort", "uniq",
    "less", "more", "file", "stat", "which", "whereis",
    "uname", "hostname", "free", "vmstat", "iostat",
    NULL
};

/* Check if command is whitelisted */
bool is_command_allowed(const char *cmd) {
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

/* Built-in: exit */
cmd_result_t builtin_exit(int argc, char **argv) {
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

/* Built-in: cd */
cmd_result_t builtin_cd(int argc, char **argv) {
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

/* Built-in: help */
cmd_result_t builtin_help(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("\n%s version 2.0.0-secure - Hardened Shell\n", "bellshell");
    printf("%.*s\n\n", 50, "==================================================");

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
    printf("  ✓ Rate limiting (60 commands/minute max)\n");
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

/* Built-in: allowed */
cmd_result_t builtin_allowed(int argc, char **argv) {
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

/* Built-in: suidscan */
cmd_result_t builtin_suidscan(int argc, char **argv) {
    /* Rate limit SUID scans to prevent abuse */
    static time_t last_suidscan = 0;
    time_t now = time(NULL);
    if (now - last_suidscan < 300) { /* 5 minutes */
        time_t wait_time = 300 - (now - last_suidscan);
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

    last_suidscan = now;

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

/* Dispatch built-in commands */
int handle_builtin(int argc, char **argv) {
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

/* Execute external command with security checks */
cmd_result_t execute_external_secure(int argc, char **argv) {
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
