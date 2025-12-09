# Bellshell - Modular Hardened Shell

A secure, restricted shell implementation with audit logging, command whitelisting, and privilege separation.

## Project Structure

```
bellshell-modular/
├── Makefile                  # Build configuration with dependency tracking
├── src/                      # Source files
│   ├── main.c               # Main event loop, input handling, shell prompt
│   ├── security.c           # Audit logging, rate limiting, signal handling
│   ├── commands.c           # Built-in commands: cd, exit, help, allowed, suidscan
│   ├── suidscan.c           # SUID/SGID binary scanner with nftw
│   └── utils.c              # Input validation, path sanitization, arg parser
└── include/                 # Header files with function prototypes
    ├── security.h           # Security subsystem API
    ├── commands.h           # Command handlers API
    ├── suidscan.h           # SUID scan context and API
    └── utils.h              # Utility function prototypes
```

## Features

### Security
- **Audit Logging**: All commands logged to syslog and local file with timestamps
- **Command Whitelisting**: Only 30 approved commands can execute externally
- **Input Sanitization**: Rejects shell metacharacters and injection attempts
- **Rate Limiting**: Max 60 commands per minute with throttling
- **Anomaly Detection**: Detects suspicious patterns (passwd, sudo, chmod, etc.)
- **Privilege Separation**: SUID scans run with dropped privileges
- **Path Validation**: Prevents directory traversal and dangerous paths

### Built-in Commands
- `cd [dir]` - Change directory (with path sanitization)
- `exit [code]` - Exit shell
- `help` - Display help and security info
- `allowed` - List whitelisted external commands
- `suidscan [options]` - Scan for SUID/SGID binaries
  - `-d <dir>` - Start directory
  - `-s` - Include SGID binaries
  - `-v` - Verbose output

### Whitelisted Commands
ls, cat, grep, find, ps, top, htop, df, du, pwd, whoami, id, date, uptime, echo, head, tail, wc, sort, uniq, less, more, file, stat, which, whereis, uname, hostname, free, vmstat, iostat

## Building

### Requirements
- GCC 4.9+ (or compatible C99 compiler)
- POSIX-compliant system (Linux, Unix, macOS, WSL)
- Standard C library with threading support

### Compilation

```bash
# Build with optimization
make

# Build with debugging symbols
make DEBUG=1

# Show available targets
make help

# Run directly
make run

# Clean build artifacts
make clean
```

The Makefile includes:
- Automatic dependency tracking (`.d` files)
- Parallel compilation support
- Separate object and binary directories
- DEBUG flag for development builds

## Installation

```bash
# Build
make

# Install to /usr/local/bin (requires root)
sudo make install
```

## Usage

```bash
./bin/bellshell
```

The shell will:
1. Initialize audit logging (syslog + local file)
2. Display security features banner
3. Set up signal handlers (SIGINT, SIGCHLD)
4. Enter main command loop

Type `help` for built-in command documentation.

## Module Organization

### main.c
- Shell event loop and prompt handling
- Input reading and rate limit checking
- Command dispatch and execution coordination
- Signal handling integration

### security.c
- Rate limit state management
- Audit logging (syslog + file)
- Signal handler setup
- Privilege dropping
- Security logging with timestamps

### commands.c
- Built-in command implementations
- Command whitelisting
- External command execution with fork/exec
- Privilege separation for SUID scanning

### suidscan.c
- SUID/SGID binary scanner using nftw(3)
- TOCTOU attack prevention
- Progress reporting
- Audit logging for findings

### utils.c
- String trimming and whitespace handling
- Shell metacharacter validation
- Path sanitization and traversal prevention
- Secure command line parsing
- Dangerous path detection

## Security Considerations

### Design Principles
1. **Principle of Least Privilege**: Drops privileges for sensitive operations
2. **Defense in Depth**: Multiple validation layers
3. **Fail Secure**: Rejects unknown commands and suspicious input
4. **Audit Trail**: All actions logged for forensics

### Input Validation
- Whitelist-based command validation
- Shell metacharacter rejection
- Path traversal prevention with realpath()
- Null byte detection
- Line length enforcement

### Logging
- Dual logging: syslog (tamper-resistant) + local file
- Timestamps with PID, UID, and priority levels
- Automatic fallback to home directory if /var/log unavailable
- File ownership verification to prevent symlink attacks

## Building on Linux/Unix

```bash
# Extract or navigate to bellshell-modular/
cd bellshell-modular

# Check configuration
make vars

# Build
make

# Test
./bin/bellshell

# Install
sudo make install
```

## Files Overview

| File | Lines | Purpose |
|------|-------|---------|
| main.c | ~150 | Shell loop, prompt, I/O |
| security.c | ~260 | Logging, rate limiting, signals |
| commands.c | ~280 | Built-in and external commands |
| suidscan.c | ~220 | SUID/SGID scanning with nftw |
| utils.c | ~170 | Input validation and sanitization |
| security.h | ~35 | Security API |
| commands.h | ~20 | Command API |
| suidscan.h | ~20 | SUID scan API |
| utils.h | ~20 | Utility API |
| Makefile | ~80 | Build automation |

**Total: ~1120 lines of modular C code**

## Compilation Flags

```makefile
CFLAGS := -Wall -Wextra -pedantic -std=c99 -pthread
```

- `-Wall -Wextra -pedantic`: Strict warnings for code quality
- `-std=c99`: C99 standard for modern C features
- `-pthread`: POSIX threading support
- `-I./include`: Include directory for headers
-
-  ## Threat Model & Limitations

BellShell is designed for use in restricted environments where users should only be able to run a small, controlled set of commands. The primary security goals are:

- **Reduce attack surface** by blocking execution of arbitrary binaries, subshells, and other dangerous commands.
- **Limit privilege escalation paths** by detecting and restricting interaction with SUID/privileged binaries where possible.
- **Improve auditability** by making user actions more predictable and easier to log or monitor.

**Out of scope / limitations:**

- BellShell does **not** replace a full OS hardening strategy (kernel hardening, mandatory access control, patch management, etc.).
- It does **not** defend against kernel-level exploits, hardware attacks, or vulnerabilities in the underlying C runtime or system libraries.
- Security guarantees depend on correct deployment (file permissions, user/group setup, and system configuration) and should be combined with other controls such as chroot/jails, containers, or VMs.

BellShell is intended as a hardened, restricted interface in labs, training environments, and controlled systems—not as a standalone, complete security solution.

## 🖥️ Demo Screenshots

### Startup & Security Enforcement
![Startup](https://raw.githubusercontent.com/ReginaldBell/bellshell/main/demo_startup.png)

### Allowed Commands
![Allowed](https://raw.githubusercontent.com/ReginaldBell/bellshell/main/demo_allowed.png)

### Blocked Commands
![Blocked](https://raw.githubusercontent.com/ReginaldBell/bellshell/main/demo_blocked.png)

## Future Enhancements

- [ ] TLS for remote audit logging
- [ ] SELinux/AppArmor integration
- [ ] Command execution time limits
- [ ] Resource usage monitoring
- [ ] 2FA for sensitive commands
- [ ] Database-backed audit logging
- [ ] Network-based rate limiting

## License
This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for more details.

## Author

Reginald Bell

## References

- POSIX.1-2008 Standard
- C99 Standard (ISO/IEC 9899:1999)
- Linux man pages: ftw(3), realpath(3), syslog(3)


