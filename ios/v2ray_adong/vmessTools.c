#include "vmessTools.h"
toto_buffer_t *toto_buffer_new_size(size_t size){
    toto_buffer_t *ptr = malloc(sizeof(toto_buffer_t));
    memset(ptr, 0, sizeof(toto_buffer_t));
    ptr->buffer = calloc(size, sizeof(uint8_t));
    ptr->cap = size;
    return ptr;
}
toto_buffer_t *toto_buffer_new(void)
{
    return toto_buffer_new_size(TOTOVE_DEFAULT_BUFSIZE);
}
void toto_buffer_free(toto_buffer_t *ptr)
{
    if (ptr) {
        if (ptr->buffer)
            free(ptr->buffer);
        free(ptr);
    }
}
void toto_buffer_ensure(toto_buffer_t *ptr, size_t n)
{
    if (ptr->cap >= n)
        return;
    int times = 1 << 1; 
    while (times * ptr->cap < n) {
        times <<= 1;
    }
    ptr->cap = times * ptr->cap;
    ptr->buffer = realloc(ptr->buffer, ptr->cap); 
}
