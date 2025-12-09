#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/commands.h"
#include "../include/security.h"
#include "../include/utils.h"

#define MAX_LINE 1024
#define MAX_ARGS 64
#define SHELL_NAME "bellshell"
#define VERSION "2.0.0-secure"
#define MAX_COMMANDS_PER_MINUTE 60

/* Forward declare shutdown flag access function */
extern volatile sig_atomic_t *get_shutdown_flag(void);

/* Display prompt */
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

/* Main shell loop */
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

    volatile sig_atomic_t *shutdown_flag = get_shutdown_flag();

    while (!*shutdown_flag) {
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
}
