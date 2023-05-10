

#include <errno.h>
#include <stdlib.h>

#include <bloom.h>
#include "ppbloom.h"

#define PING 0
#define PONG 1

static struct bloom ppbloom[2];
static int bloom_count[2];
static int current;
static int entries;
static double error;

int
ppbloom_init(int n, double e)
{
    int err;
    entries = n / 2;
    error   = e;

    err = bloom_init(ppbloom + PING, entries, error);
    if (err)
        return err;

    err = bloom_init(ppbloom + PONG, entries, error);
    if (err)
        return err;

    bloom_count[PING] = 0;
    bloom_count[PONG] = 0;

    current = PING;

    return 0;
}

int
ppbloom_check(const void *buffer, size_t len)
{
    int ret;

    ret = bloom_check(ppbloom + PING, buffer, (int)len);
    if (ret)
        return ret;

    ret = bloom_check(ppbloom + PONG, buffer, (int)len);
    if (ret)
        return ret;

    return 0;
}

int
ppbloom_add(const void *buffer, size_t len)
{
    int err;
    err = bloom_add(ppbloom + current, buffer, (int)len);
    if (err == -1)
        return err;

    bloom_count[current]++;

    if (bloom_count[current] >= entries) {
        bloom_count[current] = 0;
        current              = current == PING ? PONG : PING;
        bloom_reset(ppbloom + current);
    }

    return 0;
}

void
ppbloom_free(void)
{
    bloom_free(ppbloom + PING);
    bloom_free(ppbloom + PONG);
}
