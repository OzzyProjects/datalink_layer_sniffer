
#include "string_utils.h"

// reserve 1 MB for malloc
// normaly created/allocated in bss/data segment
static unsigned char heap_memory[1024 * 1024];

// index of last element in the fake "heap memory"
static size_t next_index = 0;

// revelant puncts in network
static const char* network_punct = "/=[]\\(){}:<>; ";

// file descriptor for the string extractor
static FILE* file = NULL;

/*---------------------------------------------------*/

void init_string_record_file(const char* filename)
{

    file = fopen(filename, "w");

    if (file == NULL){
        perror("Fatal error while creating string extractor file\n");
        exit(EXIT_FAILURE);
    }
}

/*---------------------------------------------------*/

void close_record_file()
{
    fclose(file);
}

/*---------------------------------------------------*/

/* fake malloc allocating nothing on the heap */
void *fake_malloc(const size_t size)
{

    void *mem_ptr;

    if(sizeof(heap_memory) - next_index < size)
        return NULL;

    mem_ptr = &heap_memory[next_index];
    next_index += size;

    return mem_ptr;
}

/*---------------------------------------------------*/

void copy_small(uint8_t *restrict dst, const uint8_t *restrict src, size_t n)
{

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

/*---------------------------------------------------*/

void copy_large(uint64_t *restrict dst, const uint64_t *restrict src, size_t n)
{
    
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

/*---------------------------------------------------*/

void *memcpy_s(void *restrict dst, const void *restrict src, size_t size)
{

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

/*---------------------------------------------------*/

void *memset_s(void* restrict ptr, const unsigned int init, size_t size)
{

    unsigned char* p = (unsigned char*)ptr;
    unsigned char value = init & 0xff;

    while (size--)
        *p++ = value;

    return ptr;
}

/*---------------------------------------------------*/

int memcmp_s(void *restrict ptr1, void *restrict ptr2, size_t size)
{

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

/*---------------------------------------------------*/

char *fake_strndup(const char* restrict string, size_t size)
{
    char *str = fake_malloc(size);

    if (str != NULL) {
        memcpy_s(str, string, size + 1);
        *(str+size) = '\0';
    }

    return str;
}

/*---------------------------------------------------*/

char *safe_strcpy(char *restrict dest, const char *restrict src, size_t size)
{
    
    if (size > 0){
        size_t len = strnlen(src, size - 1);
        memcpy_s(dest, src, len);
        *(dest + len) = '\0';
    }

    return dest;
}

/*---------------------------------------------------*/

size_t strlcpy(char *dst, const char *src, size_t dst_size)
{
    size_t len = strlen(src);

    if (dst_size) {
        size_t bl = (len < dst_size-1 ? len : dst_size - 1);
        ((char*)memcpy(dst, src, bl))[bl] = 0;
    }

    return len;
}

/*---------------------------------------------------*/

void *memcpy_asm(void *dest, const void *src, size_t n)
{

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

/*---------------------------------------------------*/

char *strcpy_asm(char *restrict dst, const char *restrict src) {

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

/*---------------------------------------------------*/

/* remove duplicate a char passed by argument to the function in the string */
unsigned char *remove_dup(unsigned char* input, unsigned char to_remove){

    unsigned char* tmp = input, *older = input;
    unsigned char* output = tmp;
    unsigned int i = 0;
    while (*older) {
        // if the older char == next char or if it's the first char, let's increment older char
        if ((*older == *tmp && *tmp == to_remove) || i == 0)
            ++older;
        else
            *++tmp = *older++;
        ++i;
    }

    return output;
}

/*---------------------------------------------------*/

/* replace ASCII control chars (0x1 to 0x20 and 0x7f) by a dot */
unsigned char *clean_str(unsigned char *restrict str){

    unsigned char* tmp = str;

    while(*str){
        if (*str < 0x20 || *str == 0x7f)
            *str = '.';
        ++str;
    }

    return remove_dup(tmp, '.');
}

/*---------------------------------------------------*/

/* print all clean substrings from packets like url, domain names avoiding garbage datas */
void print_strings(unsigned char *restrict buffer, int size){

    unsigned char* tmp = buffer;
    int i = 0;
    unsigned nbr_punct = 0;
    unsigned nbr_alpha = 0;

    while(i < size){
        if (isprint(*tmp)){
            unsigned char* substr = tmp;
            int j = 0;

            // while if it's printable char or any kind of dot representing ctrl chars 
            while(isprint(*tmp) || (*tmp < 0x20 && *tmp) || isspace(*tmp)){

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

            if (j > STRING_REVELANT_MIN_SIZE){

                *(substr + j) = '\0';
		    
		        /* avoiding division by zero here */
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

    printf("\n");

}

/*---------------------------------------------------*/