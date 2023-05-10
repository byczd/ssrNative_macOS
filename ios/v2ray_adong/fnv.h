#if !defined(__FNV_H__)
#define __FNV_H__
#include <sys/types.h>
#define FNV_VERSION "5.0.2"	
typedef u_int32_t Fnv32_t;
#define FNV0_32_INIT ((Fnv32_t)0)
#define FNV1_32_INIT ((Fnv32_t)0x811c9dc5)
#define FNV1_32A_INIT FNV1_32_INIT
#include "longlong.h"
#if defined(HAVE_64BIT_LONG_LONG)
typedef u_int64_t Fnv64_t;
#else 
typedef struct {
    u_int32_t w32[2]; 
} Fnv64_t;
#endif 
#if defined(HAVE_64BIT_LONG_LONG)
#define FNV0_64_INIT ((Fnv64_t)0)
#else 
extern const Fnv64_t fnv0_64_init;
#define FNV0_64_INIT (fnv0_64_init)
#endif 
#if defined(HAVE_64BIT_LONG_LONG)
#define FNV1_64_INIT ((Fnv64_t)0xcbf29ce484222325ULL)
#define FNV1A_64_INIT FNV1_64_INIT
#else 
extern const fnv1_64_init;
extern const Fnv64_t fnv1a_64_init;
#define FNV1_64_INIT (fnv1_64_init)
#define FNV1A_64_INIT (fnv1a_64_init)
#endif 
enum fnv_type {
    FNV_NONE = 0,	
    FNV0_32 = 1,	
    FNV1_32 = 2,	
    FNV1a_32 = 3,	
    FNV0_64 = 4,	
    FNV1_64 = 5,	
    FNV1a_64 = 6,	
};
struct test_vector {
    void *buf;		
    int len;		
};
struct fnv0_32_test_vector {
    struct test_vector *test;	
    Fnv32_t fnv0_32;		
};
struct fnv1_32_test_vector {
    struct test_vector *test;	
    Fnv32_t fnv1_32;		
};
struct fnv1a_32_test_vector {
    struct test_vector *test;	
    Fnv32_t fnv1a_32;		
};
struct fnv0_64_test_vector {
    struct test_vector *test;	
    Fnv64_t fnv0_64;		
};
struct fnv1_64_test_vector {
    struct test_vector *test;	
    Fnv64_t fnv1_64;		
};
struct fnv1a_64_test_vector {
    struct test_vector *test;	
    Fnv64_t fnv1a_64;		
};
extern Fnv32_t fnv_32_buf(void *buf, size_t len, Fnv32_t hashval);
extern Fnv32_t fnv_32_str(char *buf, Fnv32_t hashval);
extern Fnv32_t fnv_32a_buf(void *buf, size_t len, Fnv32_t hashval);
extern Fnv32_t fnv_32a_str(char *buf, Fnv32_t hashval);
extern Fnv64_t fnv_64_buf(void *buf, size_t len, Fnv64_t hashval);
extern Fnv64_t fnv_64_str(char *buf, Fnv64_t hashval);
extern Fnv64_t fnv_64a_buf(void *buf, size_t len, Fnv64_t hashval);
extern Fnv64_t fnv_64a_str(char *buf, Fnv64_t hashval);
extern struct test_vector fnv_test_str[];
extern struct fnv0_32_test_vector fnv0_32_vector[];
extern struct fnv1_32_test_vector fnv1_32_vector[];
extern struct fnv1a_32_test_vector fnv1a_32_vector[];
extern struct fnv0_64_test_vector fnv0_64_vector[];
extern struct fnv1_64_test_vector fnv1_64_vector[];
extern struct fnv1a_64_test_vector fnv1a_64_vector[];
extern void unknown_hash_type(char *prog, enum fnv_type type, int code);
extern void print_fnv32(Fnv32_t hval, Fnv32_t mask, int verbose, char *arg);
extern void print_fnv64(Fnv64_t hval, Fnv64_t mask, int verbose, char *arg);
#endif 
