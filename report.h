#ifndef REPORT_H
#define REPORT_H

void set_program_name(const char* name);

void report(const char* fmt, ...);
void report_error(const char* fmt, ...);

#endif  /* REPORT_H */
