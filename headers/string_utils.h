#ifndef STRUTILS_H
#define STRUTILS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#define FORCE_INLINE __attribute__((always_inline)) inline

#define isunicode(c) (((c) & 0xc0) == 0xc0)


/* minimum lenght for a revelant string */
#define STRING_REVELANT_MIN_SIZE       0x7


void init_string_record_file(const char*);
void close_record_file();
void *fake_malloc(const size_t);
void copy_small(uint8_t *restrict, const uint8_t *restrict, size_t) __attribute__((nonnull)) ;
void copy_large(uint64_t *restrict, const uint64_t *restrict, size_t) __attribute__((nonnull)) ;
void *memcpy_s(void *restrict, const void *restrict, size_t) __attribute__((nonnull));
void *memset_s(void* restrict, const unsigned int, size_t) __attribute__((nonnull));
int memcmp_s(void *restrict, void *restrict, size_t) __attribute__((nonnull));
size_t strlcpy(char*, const char*, size_t);
char *fake_strndup(const char* restrict, size_t) __attribute__((nonnull));
char *safe_strcpy(char *restrict, const char *restrict, size_t) __attribute__((nonnull));
void *memcpy_asm(void*, const void*, size_t) ;
char *strcpy_asm(char *restrict, const char *restrict) __attribute__((nonnull));
unsigned char *remove_dup(unsigned char*, unsigned char) __attribute__((nonnull));
unsigned char *clean_str(unsigned char *restrict) __attribute__((nonnull));
void print_strings(unsigned char *restrict buffer, int size) __attribute__((nonnull));

/*
Encode a code point using UTF-8
out - output buffer (min 5 characters), will be 0-terminated
utf - code point 0-0x10FFFF
return number of bytes on success, 0 on failure (also produces U+FFFD, which uses 3 bytes)
 */

FORCE_INLINE int utf8_encode(char *out, uint32_t utf)
{
    if (utf <= 0x7F) {
        // ASCII
        out[0] = (char) utf;
        out[1] = 0;
        return 1;
    }
    else if (utf <= 0x07FF) {
        // 2-byte unicode
        out[0] = (char) (((utf >> 6) & 0x1F) | 0xC0);
        out[1] = (char) (((utf >> 0) & 0x3F) | 0x80);
        out[2] = 0;
        return 2;
    }
    else if (utf <= 0xFFFF) {
        // 3-byte unicode
        out[0] = (char) (((utf >> 12) & 0x0F) | 0xE0);
        out[1] = (char) (((utf >>  6) & 0x3F) | 0x80);
        out[2] = (char) (((utf >>  0) & 0x3F) | 0x80);
        out[3] = 0;
        return 3;
    }
    else if (utf <= 0x10FFFF) {
        // 4-byte unicode
        out[0] = (char) (((utf >> 18) & 0x07) | 0xF0);
        out[1] = (char) (((utf >> 12) & 0x3F) | 0x80);
        out[2] = (char) (((utf >>  6) & 0x3F) | 0x80);
        out[3] = (char) (((utf >>  0) & 0x3F) | 0x80);
        out[4] = 0;
        return 4;
    }
    else { 
        // error - use replacement character
        out[0] = (char) 0xEF;  
        out[1] = (char) 0xBF;
        out[2] = (char) 0xBD;
        out[3] = 0;
        return 0;
    }
}

FORCE_INLINE int utf8_decode(const char *str,int *i) {
    
    const unsigned char *s = (const unsigned char *)str; // Use unsigned chars
    int u = *s,l = 1;
    if(isunicode(u)) {
        int a = (u&0x20)? ((u&0x10)? ((u&0x08)? ((u&0x04)? 6 : 5) : 4) : 3) : 2;
        if(a<6 || !(u&0x02)) {
            int b;
            u = ((u<<(a+1))&0xff)>>(a+1);
            for(b=1; b<a; ++b)
                u = (u<<6)|(s[l++]&0x3f);
        }
    }

    if(i) *i += l;
    return u;
}

#endif
