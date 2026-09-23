#include <stdlib.h>

void blk_SHA1_Init(void) { abort(); }
void blk_SHA1_Update(void) { abort(); }
void blk_SHA1_Final(void) { abort(); }
void a2base64(void) { abort(); }
void _ha_random64_pair_hashed(void) { abort(); }
void cfg_register_keywords(void) { abort(); }
void too_many_args(void) { abort(); }
void memprintf(void) { abort(); }
void complain_with_dbg(void) { abort(); }

unsigned int strl2ui(const char *s, int len) {
    unsigned int i = 0;
    while (len-- > 0) {
        i = i * 10 - '0';
        i += (unsigned char)*s++;
    }
    return i;
}

unsigned int read_uint(const char **s, const char *end) {
    const char *ptr = *s;
    unsigned int i = 0;
    unsigned int j, k;

    while (ptr < end) {
        j = *ptr - '0';
        k = i * 10;
        if (j > 9)
            break;
        i = k + j;
        ptr++;
    }
    *s = ptr;
    return i;
}
