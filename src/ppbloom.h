

#ifndef _PPBLOOM_
#define _PPBLOOM_

#include <stddef.h>

int ppbloom_init(int entries, double error);
int ppbloom_check(const void *buffer, size_t len);
int ppbloom_add(const void *buffer, size_t len);
void ppbloom_free(void);

#endif

