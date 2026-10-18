// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// LD_PRELOAD allocation counter for the shipped binary (zero-malloc-per-request work, Z1).
// Counts malloc/calloc/realloc/free/aligned calls and bytes process-wide; every 20 ms a
// thread writes them to the file named by $ALLOCSHIM_OUT (and a size histogram to
// $ALLOCSHIM_OUT.hist). Build: cc -O2 -shared -fPIC -o shim.so shim.c -ldl -lpthread
// Driven by harness/malloc_per_request.py.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
static void *(*r_malloc)(size_t); static void *(*r_calloc)(size_t,size_t);
static void *(*r_realloc)(void*,size_t); static void (*r_free)(void*);
static int (*r_pma)(void**,size_t,size_t); static void *(*r_aa)(size_t,size_t);
static void *(*r_ma)(size_t,size_t);
static unsigned long c_malloc,c_calloc,c_realloc,c_free,c_align,b_alloc;
static unsigned long hist[1025];
#define H(n) A(hist[(n)>1023?1024:(n)],1)
static char boot[65536]; static size_t bootoff; static int resolving;
#define A(x,n) __atomic_fetch_add(&x,n,__ATOMIC_RELAXED)
static void resolve(void){
  if(r_malloc||resolving) return; resolving=1;
  r_calloc=dlsym(RTLD_NEXT,"calloc"); r_realloc=dlsym(RTLD_NEXT,"realloc");
  r_free=dlsym(RTLD_NEXT,"free"); r_pma=dlsym(RTLD_NEXT,"posix_memalign");
  r_aa=dlsym(RTLD_NEXT,"aligned_alloc"); r_ma=dlsym(RTLD_NEXT,"memalign");
  r_malloc=dlsym(RTLD_NEXT,"malloc"); resolving=0; }
static int isboot(void*p){return (char*)p>=boot&&(char*)p<boot+sizeof boot;}
void *malloc(size_t n){ if(!r_malloc){resolve(); if(!r_malloc){void*p=boot+bootoff;bootoff+=(n+15)&~15UL;return p;}} A(c_malloc,1);A(b_alloc,n);H(n);return r_malloc(n);}
void *calloc(size_t a,size_t b){ if(!r_malloc){resolve(); if(!r_malloc){void*p=boot+bootoff;bootoff+=((a*b)+15)&~15UL;return p;}} A(c_calloc,1);A(b_alloc,a*b);return r_calloc(a,b);}
void *realloc(void*p,size_t n){ resolve(); if(p&&isboot(p)){void*q=malloc(n);memcpy(q,p,n);return q;} A(c_realloc,1);A(b_alloc,n);H(n);return r_realloc(p,n);}
void free(void*p){ if(!p||isboot(p))return; resolve(); A(c_free,1); r_free(p);}
int posix_memalign(void**o,size_t al,size_t n){resolve();A(c_align,1);A(b_alloc,n);return r_pma(o,al,n);}
void *aligned_alloc(size_t al,size_t n){resolve();A(c_align,1);A(b_alloc,n);return r_aa(al,n);}
void *memalign(size_t al,size_t n){resolve();A(c_align,1);A(b_alloc,n);return r_ma(al,n);}
static void dump(void){ char path[512],buf[256]; const char*o=getenv("ALLOCSHIM_OUT"); if(!o)return; snprintf(path,sizeof path,"%s",o);
  int fd=open(path,O_WRONLY|O_CREAT,0644); if(fd<0)return;
  int l=snprintf(buf,sizeof buf,"malloc %lu\ncalloc %lu\nrealloc %lu\nfree %lu\nalign %lu\nbytes %lu\n",c_malloc,c_calloc,c_realloc,c_free,c_align,b_alloc);
  ssize_t r=pwrite(fd,buf,l,0); (void)r; close(fd);
  snprintf(path,sizeof path,"%s.hist",o); fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd<0)return; for(int i=0;i<=1024;i++) if(hist[i]){l=snprintf(buf,sizeof buf,"%d %lu\n",i,hist[i]); r=write(fd,buf,l);} close(fd);}
static void *th(void*a){(void)a; for(;;){dump();usleep(20000);} return 0;}
__attribute__((constructor)) static void init(void){ resolve(); pthread_t t; pthread_create(&t,0,th,0); pthread_detach(t);}
__attribute__((destructor)) static void fini(void){dump();}
