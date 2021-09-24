#include "os.h"

#define SAFE_MEMMOVE(dest, dest_size, src, src_size, n, ERR_EXPR) \
    {                                                             \
        if ((n) < 0 || (n) > (dest_size) || (n) > (src_size)) {   \
            ERR_EXPR;                                             \
        } else {                                                  \
            os_memmove(dest, src, n);                             \
        }                                                         \
    }
