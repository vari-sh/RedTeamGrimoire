#define _CRT_SECURE_NO_WARNINGS
#include "logger.h"
#include <stdarg.h>

FILE* logfile = NULL;

// Open log file and disable buffering
BOOL init_logger(const char* path) {
    logfile = fopen(path, "a");
    if (!logfile) return FALSE;
    setvbuf(logfile, NULL, _IONBF, 0); // Disable buffering
    return TRUE;
}

// Close log file
void close_logger(void) {
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
}

// Internal log formatter
static void log_formatted(const char* prefix, const char* fmt, va_list args) {
    if (!logfile) return;

    fprintf(logfile, "[%s] ", prefix);
    vfprintf(logfile, fmt, args);
    fprintf(logfile, "\n");
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_formatted("*", fmt, args);
    va_end(args);
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_formatted("ERROR", fmt, args);
    va_end(args);
}

void log_success(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_formatted("+", fmt, args);
    va_end(args);
}
