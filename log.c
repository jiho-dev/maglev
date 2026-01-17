#include <stdio.h>
#include <stdarg.h>

#include "log.h"

//LogLevel current_log_level = LOG_LEVEL_WARN; 
LogLevel current_log_level = LOG_LEVEL_DEBUG; 

const char* log_level_strings[LOG_LEVEL_COUNT] = {
    "[ERROR]",
    "[WARN]",
    "[INFO]",
    "[DEBUG]"
};

void my_log_printf(LogLevel level, const char* format, ...) {
    if (level > current_log_level) {
        return;
    }

    printf("%s ", log_level_strings[level]);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}



