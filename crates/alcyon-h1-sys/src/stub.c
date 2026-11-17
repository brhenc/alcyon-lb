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
void cfg_register_section(void) { abort(); }
void cebuis_ofs_delete(void) { abort(); }
void chunk_printf(void) { abort(); }
void alertif_too_many_args_idx(void) { abort(); }
void cli_register_kw(void) { abort(); }
void alertif_too_many_args(void) { abort(); }
void find_word_index_in_array(void) { abort(); }
void __b_putblk(void) { abort(); }
void hap_register_post_deinit(void) { abort(); }
void chunk_appendf(void) { abort(); }
void ha_alert(void) { abort(); }
void applet_reserve_svcctx(void) { abort(); }
/* data symbols the http-hardening code references; never read by the h1/http parsers under test */
char global[65536];
char trash[64];
void cebuis_ofs_next(void) { abort(); }
void cebuis_ofs_first(void) { abort(); }
void cebuis_ofs_insert(void) { abort(); }
void cebuis_ofs_lookup(void) { abort(); }
void invalid_char(void) { abort(); }
void cli_has_level(void) { abort(); }
void ci_putblk(void) { abort(); }

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
