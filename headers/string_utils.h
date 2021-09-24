/* 
some C standard functions reimplemented to make some experiments 
exemple : fake malloc that doesn't allocate dynamic memory but it is based on 1mb size static array
other : memcpy etc... in inline GNU assembly
i don't know if they are faster but i don't think so
*/

#ifndef STRUTILS
#define STRUTILS

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>

#define FORCE_INLINE __attribute__((always_inline)) inline

// static array for fake malloc
static unsigned char heap_memory[1024 * 1024]; //reserve 1 MB for malloc

// next position
static size_t next_index = 0;

// fake malloc
void *malloc_s(const size_t size){

    void *mem_ptr;

    if(sizeof(heap_memory) - next_index < size)
        return NULL;

    mem_ptr = &heap_memory[next_index];
    next_index += size;

    return mem_ptr;
}

FORCE_INLINE void __attribute__((nonnull)) copy_small(uint8_t *restrict dst, const uint8_t *restrict src, size_t n){

    if (n >= 8){
        *(uint64_t *restrict)dst = *(const uint64_t *restrict)src;
        return;
    }

    if (n >= 4){
        *(uint32_t *restrict)dst = *(const uint32_t *restrict)src;
        dst += 4;
        src += 4;
    }

    if (n & 2){
        *(uint16_t *restrict)dst = *(const uint16_t *restrict)src;
        dst += 2;
        src += 2;
    }

    if (n & 1)
        *dst = *src;
}

FORCE_INLINE void __attribute__((nonnull)) copy_large(uint64_t *restrict dst, const uint64_t *restrict src, size_t n){
    
    size_t chunks, offset;

    chunks = n >> 3;
    offset = n - (chunks << 3);

    while (chunks--)
    {
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
    }

    while (offset--)
        *dst++ = *src++;
}

// memcpy reimplemented with aligned datas

void __attribute__((nonnull)) *memcpy_s(void *restrict dst, const void *restrict src, size_t size){

    uint8_t *dst8;
    const uint8_t *src8;
    size_t qwords, aligned_size;

    dst8 = (uint8_t*)dst;
    src8 = (const uint8_t*)src;
    qwords = size >> 3;

    if (size > 8){
        copy_large((uint64_t*)dst, (const uint64_t*)src, qwords);
        return dst;
    }

    aligned_size = qwords << 3;
    size -= aligned_size;
    dst8 += aligned_size;
    src8 += aligned_size;

    copy_small(dst8, src8, size);

    return dst;
}

void __attribute__((nonnull)) *memset_s(void* restrict ptr, const unsigned int init, size_t size){

    unsigned char* p = (unsigned char*)ptr;
    unsigned char value = init & 0xff;

    while (size--)
        *p++ = value;

    return ptr;
}

int __attribute__((nonnull)) memcmp_s(void *restrict ptr1, void *restrict ptr2, size_t size){

    unsigned char *tmp_ptr1 = ptr1;
    unsigned char *tmp_ptr2 = ptr2;

    while(size--)
    {
        if (*tmp_ptr2 != *tmp_ptr1)
            return (*tmp_ptr2 - *tmp_ptr1);

        tmp_ptr1++;
        tmp_ptr2++;
    }

    return 0;
}

char __attribute__((nonnull)) *strncpy_s(char *restrict dest, char *restrict src, size_t size){
	
	char *tmp = dest;

	while(size--)
		*tmp++ = *src++;

	return dest;
}

char __attribute__((nonnull)) *strndup_s(const char* restrict string, size_t size)
{
    char *str = malloc_s(size);

    if (str != NULL) {
        memcpy_s(str, string, size + 1);
        *(str+size) = '\0';
    }

    return str;
}

FORCE_INLINE size_t __attribute__((nonnull)) strlen_s(const char *restrict str){

    size_t sum = 0;

    while (*str++) {
        if (sum == 1024) return 0;
        sum++;
    }

    return sum;
}

FORCE_INLINE int __attribute__((nonnull)) strncmp_s(const char *restrict str1, const char *restrict str2, size_t size){
    
    while (size-- && *str1 == *str2){ 
        ++str1; 
        ++str2; 
    }

    return (int)(unsigned char)(*str1) - (int)(unsigned char)(*str2);
}

char __attribute__((nonnull)) *safe_strcpy(char *restrict dest, size_t size, const char *restrict src) {
    
    if (size > 0){
        size_t len = strnlen(src, size - 1);
        memcpy_s(dest, src, len);
        *(dest+len) = '\0';
    }

    return dest;
}

FORCE_INLINE unsigned char tolower_s(unsigned char c){

    if (isupper(c))
        c ^= 0x20;

    return c;
}


FORCE_INLINE unsigned char toupper_s(unsigned char c){

    if (islower(c))
        c ^= 0x20;

    return c;
 }

char __attribute__((nonnull)) *tolower_str(char *restrict str){

    unsigned char *mystr = (unsigned char *)str;

    while (*mystr){
        *mystr = tolower_s(*mystr);
        mystr++;
    }

    return str;
}

FORCE_INLINE void __attribute__((nonnull)) *memcpy_asm(void *dest, const void *src, size_t n){

    long d0, d1, d2;
     
    __asm__ __volatile__(
    "rep ; movsq\n\t""movq %4,%%rcx\n\t""rep ; movsb\n\t": "=&c" (d0),                                                                                   
    "=&D" (d1),
    "=&S" (d2): "0" (n >> 3), 
    "g" (n & 7), 
    "1" (dest),
    "2" (src): "memory");  
  
    return dest;
}

FORCE_INLINE char __attribute__((nonnull)) *strcpy_asm(char *restrict dst, const char *restrict src) {

    int rsrc, rdst;

    __asm__ __volatile__(
    "1: \tlodsb\n\t;"
    "stosb\n\t;"
    "testb %%al,%%al\n\t;"
    "jne 1b;"
    : "=&S" (rsrc), "=&D" (rdst)
    : "0" (src),"1" (dst));

    return dst;
}


#endif
