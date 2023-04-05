#include <stdio.h>
#include <stdarg.h>

#include "report.h"

static const char* program_name = NULL;

void
set_program_name(const char* name)
{
    program_name = name;
}

void
report(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}

void
report_error(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", program_name);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
