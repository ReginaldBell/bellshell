#ifndef COMMANDS_H
#define COMMANDS_H
#include <stdbool.h>
#include "security.h"

/* Built-in command handlers */
cmd_result_t builtin_exit(int argc, char **argv);
cmd_result_t builtin_cd(int argc, char **argv);
cmd_result_t builtin_help(int argc, char **argv);
cmd_result_t builtin_allowed(int argc, char **argv);
cmd_result_t builtin_suidscan(int argc, char **argv);

/* Command dispatch */
int handle_builtin(int argc, char **argv);

/* External command execution */
cmd_result_t execute_external_secure(int argc, char **argv);

/* Command whitelisting */
bool is_command_allowed(const char *cmd);

#endif /* COMMANDS_H */
