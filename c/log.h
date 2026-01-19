#ifndef __LOG_H__
#define __LOG_H__

typedef enum {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_COUNT
} LogLevel;

void my_log_printf(LogLevel level, const char* format, ...);

#define VLOG_ERROR(format, ...) my_log_printf(LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define VLOG_WARN(format, ...)  my_log_printf(LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define VLOG_INFO(format, ...)  my_log_printf(LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define VLOG_DEBUG(format, ...) my_log_printf(LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)

#endif
