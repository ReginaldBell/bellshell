#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>

/* Input sanitization and validation */
void trim_newline(char *s);
void trim_whitespace(char *s);
bool is_safe_argument(const char *arg);
bool sanitize_path(const char *path, char *sanitized, size_t size);

/* Command line parsing */
int parse_line_secure(char *line, char **argv);

/* Path validation */
bool is_safe_scan_path(const char *path);

#endif /* UTILS_H */
