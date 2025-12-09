# Makefile for bellshell
# Modular hardened shell with audit logging and security features

CC := gcc
CFLAGS := -Wall -Wextra -pedantic -std=c99 -pthread
CFLAGS += -I./include

# Optional: Add debugging symbols
ifdef DEBUG
    CFLAGS += -g -O0
else
    CFLAGS += -O2
endif

# Directories
SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj
BIN_DIR := bin

# Files
SOURCES := $(wildcard $(SRC_DIR)/*.c)
HEADERS := $(wildcard $(INC_DIR)/*.h)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJECTS:.o=.d)
EXECUTABLE := $(BIN_DIR)/bellshell

# Default target
.PHONY: all
all: $(EXECUTABLE)

# Create directories
$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

# Dependency generation and compilation
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Link executable
$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@
	@echo "✓ Built: $@"

# Include auto-generated dependencies
-include $(DEPS)

# Clean build artifacts
.PHONY: clean
clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "✓ Cleaned build artifacts"

# Clean everything including backups
.PHONY: distclean
distclean: clean
	@rm -f *~
	@echo "✓ Cleaned all artifacts and backups"

# Install (optional)
.PHONY: install
install: $(EXECUTABLE)
	@install -D -m 0755 $(EXECUTABLE) /usr/local/bin/bellshell
	@echo "✓ Installed to /usr/local/bin/bellshell"

# Run the executable
.PHONY: run
run: $(EXECUTABLE)
	@$(EXECUTABLE)

# Show help
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the bellshell executable (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  distclean - Remove all generated files"
	@echo "  install   - Install bellshell to /usr/local/bin (requires root)"
	@echo "  run       - Build and run bellshell"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Environment:"
	@echo "  DEBUG=1   - Build with debugging symbols (-g -O0)"
	@echo ""
	@echo "Example: make DEBUG=1"

# Print variables (for debugging)
.PHONY: vars
vars:
	@echo "CC: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "EXECUTABLE: $(EXECUTABLE)"
