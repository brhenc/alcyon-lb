#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include "import/slz.h"
int main(void){
    printf("sizeof(struct slz_stream) = %zu bytes\n", sizeof(struct slz_stream));
    printf("sizeof(z_stream)          = %zu bytes (plus deflateInit's heap state)\n", sizeof(z_stream));
    z_stream zs; memset(&zs,0,sizeof zs);
    deflateInit2(&zs,1,Z_DEFLATED,15+16,8,Z_DEFAULT_STRATEGY);
    /* zlib reports its own state size via deflateBound-independent means; use the documented formula */
    printf("zlib deflate state, windowBits=15 memLevel=8: ~%d bytes (documented (1<<(15+2))+(1<<(8+9)))\n",
           (1<<(15+2))+(1<<(8+9)));
    deflateEnd(&zs);
    return 0;
}
