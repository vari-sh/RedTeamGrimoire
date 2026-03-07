#pragma once
#include <stdio.h>
#include <Windows.h>

// Global log file handle
extern FILE* logfile;

// Initialize logging (opens the log file)
BOOL init_logger(const char* path);

// Clean up logging (closes the log file)
void close_logger(void);

// Log helpers
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);
void log_success(const char* fmt, ...);
