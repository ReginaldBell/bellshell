#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/utils.h"

#define MAX_ARGS 64

/* Trim trailing newline */
void trim_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '\n') {
        s[len - 1] = '\0';
    }
}

/* Trim leading and trailing whitespace */
void trim_whitespace(char *s) {
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
bool is_safe_argument(const char *arg) {
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
bool sanitize_path(const char *path, char *sanitized, size_t size) {
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
int parse_line_secure(char *line, char **argv) {
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
            return 0;
        }
    }

    return argc;
}

/* Validate that path is safe for scanning */
bool is_safe_scan_path(const char *path) {
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
