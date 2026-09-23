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
    strcpy((char*)http,"HTTP/1.1 200 OK\r\nServer: ibex\r\nContent-Type: text/html\r\n\r\n<html><body><h1>hi</h1></body></html>");
    static unsigned char inc[1024]; for(int i=0;i<1024;i++) inc[i]=i&0xff;
    printf("[\n");
    const char *fmts[3]={"rfc1951","rfc1952","rfc1950"};
    for(int f=0;f<3;f++) for(int lv=0;lv<2;lv++){
        emit("empty",fmts[f],lv,(const unsigned char*)"",0);
        emit("hello",fmts[f],lv,(const unsigned char*)hello,strlen(hello));
        emit("repeat_4k_A",fmts[f],lv,rep,sizeof rep);
        emit("http_response",fmts[f],lv,http,strlen((char*)http));
        emit("incompressible_1k",fmts[f],lv,inc,sizeof inc);
    }
    printf("  null\n]\n");
    return 0;
}
