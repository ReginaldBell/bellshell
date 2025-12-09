#ifndef SECURITY_H
#define SECURITY_H
#include <stdbool.h>
#include <sys/types.h>
#include <syslog.h>

/* Rate limiting and anomaly detection */
typedef struct {
    time_t window_start;
    int command_count;
    int failed_commands;
    int suspicious_commands;
    time_t last_suidscan;
} rate_limit_state_t;

/* Command execution result codes */
typedef enum {
    CMD_SUCCESS = 0,
    CMD_ERROR = 1,
    CMD_EXIT = 2
} cmd_result_t;

/* Initialization and cleanup */
int init_secure_logging(void);
void close_secure_logging(void);

/* Logging and auditing */
void audit_log_secure(int priority, const char *level, const char *message);

/* Rate limiting */
bool check_rate_limit(void);
void record_command_result(cmd_result_t result, const char *cmd);

/* Signal handling */
void setup_signal_handlers(void);

/* Privilege management */
int drop_privileges_permanently(void);

#endif /* SECURITY_H */
