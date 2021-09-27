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
#define isunicode(c) (((c)&0xc0)==0xc0)

// minimum lenght for a revelant string

#define STRING_MIN_SIZE 8

#undef isalpha
FORCE_INLINE int isalpha(int c){
    return((c >='a' && c <='z') || (c >='A' && c <='Z'));
}

static unsigned char heap_memory[1024 * 1024]; //reserve 1 MB for malloc

// revelant puncts in network
static const unsigned char* network_punct = "/=[](){}:<>;";

static size_t next_index = 0;

// file descriptor for the string extractor
static FILE* file = NULL;

void init_string_record_file(const char* filename){

    file = fopen(filename, "w");
    if (file == NULL){
        perror("fatal error while creating string extractor file\n");
        exit(EXIT_FAILURE);
    }
}

// fake malloc
void *fake_malloc(const size_t size){

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
    char *str = fake_malloc(size);

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

// replace all chars from 0x1 to 0x8 by a point in ascii

unsigned char __attribute__((nonnull)) *clean_str(unsigned char *restrict str){

    unsigned char* tmp = str;

    while(*str){
        if (*str < 0x15)
            *str = '.';
        str++;
    }

        return tmp;
}

// print all clean substrings from packets like url, domain names avoiding garbage data

void __attribute__((nonnull)) print_strings(unsigned char *restrict buffer, int size){

    unsigned char* tmp = buffer;
    int i = 0;
    unsigned nbr_punct = 0;
    unsigned nbr_alpha = 0;

    while(i < size){
        if (isprint(*tmp)){
            unsigned char* substr = tmp;
            int j = 0;

            // while if it's printable char or any kind of dot representing ctrl chars 
            while(isprint(*tmp) || (*tmp < 0x15 && *tmp)){

                // if it's alphanumeric char, let's increment counter
                if (isalnum(*tmp))
                    nbr_alpha++;

                // counting punct chars too to avoid garbage strings
                // keeping / {} () for http requests with json ect...

                if (ispunct(*tmp) && strchr(network_punct, *tmp) == NULL)
                    nbr_punct++;

                tmp++;
                j++;
            }
            
            // if the substring is long enough (< 8) = revelant string content

            if (j > STRING_MIN_SIZE){

                *(substr + j) = '\0';
		    
		// avoiding division by zeo here
                nbr_punct = (!nbr_punct) ? 1 : nbr_punct;

                // print only revelant strings
                if (nbr_alpha > nbr_punct && strlen((char*)substr) / nbr_punct > 3){
                    fprintf(file, "%s\n", clean_str(substr));
                    printf("%s\n", clean_str(substr));
                }
            }
            i += j;
        }
        else{
            i++;
            tmp++;
        }
    }

}

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
            int b,p = 0;
            u = ((u<<(a+1))&0xff)>>(a+1);
            for(b=1; b<a; ++b)
                u = (u<<6)|(s[l++]&0x3f);
        }
    }

    if(i) *i += l;
    return u;
}

#endif
