#include <stdlib.h>
#include "fnv.h"
#define FNV_32_PRIME ((Fnv32_t)0x01000193)
Fnv32_t
fnv_32a_buf(void *buf, size_t len, Fnv32_t hval)
{
    unsigned char *bp = (unsigned char *)buf;	
    unsigned char *be = bp + len;		
    while (bp < be) {
	hval ^= (Fnv32_t)*bp++;
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }
    return hval;
}
Fnv32_t
fnv_32a_str(char *str, Fnv32_t hval)
{
    unsigned char *s = (unsigned char *)str;	
    while (*s) {
	hval ^= (Fnv32_t)*s++;
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }
    return hval;
}
