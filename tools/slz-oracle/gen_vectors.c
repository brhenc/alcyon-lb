#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "import/slz.h"
static void emit(const char*name,const char*fmt,int level,const unsigned char*in,long ilen){
    struct slz_stream s; unsigned char out[262144]; long n=0; int k;
    if(!strcmp(fmt,"rfc1951")) slz_rfc1951_init(&s,level);
    else if(!strcmp(fmt,"rfc1952")) slz_rfc1952_init(&s,level);
    else slz_rfc1950_init(&s,level);
    n = (!strcmp(fmt,"rfc1951")) ? slz_rfc1951_encode(&s,out,in,ilen,0)
      : (!strcmp(fmt,"rfc1952")) ? slz_rfc1952_encode(&s,out,in,ilen,0)
                                 : slz_rfc1950_encode(&s,out,in,ilen,0);
    k = (!strcmp(fmt,"rfc1951")) ? slz_rfc1951_finish(&s,out+n)
      : (!strcmp(fmt,"rfc1952")) ? slz_rfc1952_finish(&s,out+n)
                                 : slz_rfc1950_finish(&s,out+n);
    n+=k;
    printf("  {\"name\":\"%s\",\"format\":\"%s\",\"level\":%d,\"in_hex\":\"",name,fmt,level);
    for(long i=0;i<ilen;i++) printf("%02x",in[i]);
    printf("\",\"out_hex\":\"");
    for(long i=0;i<n;i++) printf("%02x",out[i]);
    printf("\",\"in_len\":%ld,\"out_len\":%ld,\"crc32\":%u},\n",ilen,n,s.crc32);
}

int main(void){
    const char *hello="Hello, world!";
    static unsigned char rep[4096]; memset(rep,'A',sizeof rep);
    static unsigned char http[512];
    strcpy((char*)http,"HTTP/1.1 200 OK\r\nServer: alcyon\r\nContent-Type: text/html\r\n\r\n<html><body><h1>hi</h1></body></html>");
    static unsigned char inc[1024]; for(int i=0;i<1024;i++) inc[i]=i&0xff;

    static unsigned char b65534[65534]; memset(b65534, 'B', 65534);
    static unsigned char b65535[65535]; memset(b65535, 'C', 65535);
    static unsigned char b65536[65536]; memset(b65536, 'D', 65536);
    static unsigned char b65537[65537]; memset(b65537, 'E', 65537);

    static unsigned char debt_cross[100000];
    srand(42);
    for (int i=0; i<65536; i++) debt_cross[i] = rand() & 0xff;
    memset(debt_cross + 65536, 'X', 4096);

    static unsigned char match_3[10] = "abc12abc34";
    static unsigned char match_258[520];
    memset(match_258, 'M', 258);
    match_258[258] = '1';
    memset(match_258 + 259, 'M', 258);
    static unsigned char match_dist_1[20];
    memset(match_dist_1, 'R', 20);
    static unsigned char match_dist_32768[32768 + 10];
    for(int i=0; i<32768 + 10; i++) match_dist_32768[i] = (i < 5) ? "match"[i] : (i & 0xff);
    memcpy(match_dist_32768 + 32768, "match", 5);

    static unsigned char all_bytes[256];
    for(int i=0; i<256; i++) all_bytes[i] = i;
    static unsigned char all_FF[256];
    memset(all_FF, 0xFF, 256);

    printf("[\n");
    const char *fmts[3]={"rfc1951","rfc1952","rfc1950"};
    for(int f=0;f<3;f++) for(int lv=0;lv<2;lv++){
        emit("empty",fmts[f],lv,(const unsigned char*)"",0);
        emit("hello",fmts[f],lv,(const unsigned char*)hello,strlen(hello));
        emit("repeat_4k_A",fmts[f],lv,rep,sizeof rep);
        emit("http_response",fmts[f],lv,http,strlen((char*)http));
        emit("incompressible_1k",fmts[f],lv,inc,sizeof inc);
        
        emit("boundary_65534",fmts[f],lv,b65534,sizeof b65534);
        emit("boundary_65535",fmts[f],lv,b65535,sizeof b65535);
        emit("boundary_65536",fmts[f],lv,b65536,sizeof b65536);
        emit("boundary_65537",fmts[f],lv,b65537,sizeof b65537);
        
        emit("debt_accounting",fmts[f],lv,debt_cross,65536 + 4096);
        
        emit("match_3",fmts[f],lv,match_3,10);
        emit("match_258",fmts[f],lv,match_258,258*2 + 1);
        emit("match_dist_1",fmts[f],lv,match_dist_1,20);
        emit("match_dist_32768",fmts[f],lv,match_dist_32768,32768 + 5);
        
        emit("all_bytes",fmts[f],lv,all_bytes,256);
        emit("all_FF",fmts[f],lv,all_FF,256);
    }
    printf("  null\n]\n");
    return 0;
}
