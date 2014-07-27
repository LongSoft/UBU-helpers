#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* Return codes */
#define ERR_SUCCESS           0
#define ERR_NOT_FOUND         1
#define ERR_FILE_OPEN         2
#define ERR_FILE_READ         3
#define ERR_INVALID_PARAMETER 4
#define ERR_OUT_OF_MEMORY     5
#define ERR_UNKNOWN_VERSION   6
#define ERR_UNKNOWN_OPTION    7

/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm
*  Returns pointer to the beginning of found pattern or NULL if not found */
uint8_t* find_pattern(uint8_t* begin, uint8_t* end, 
                      const uint8_t* pattern, size_t plen)
{
    size_t scan = 0;
    size_t bad_char_skip[256];
    size_t last;
    size_t slen;

    if (plen == 0 || !begin || !pattern || !end || end <= begin)
        return NULL;

    slen = end - begin;

    for (scan = 0; scan <= 255; scan++)
        bad_char_skip[scan] = plen;

    last = plen - 1;

    for (scan = 0; scan < last; scan++)
        bad_char_skip[pattern[scan]] = last - scan;

    while (slen >= plen)
    {
        for (scan = last; begin[scan] == pattern[scan]; scan--)
            if (scan == 0)
                return begin;

        slen    -= bad_char_skip[begin[last]];
        begin   += bad_char_skip[begin[last]];
    }

    return NULL;
}

/* Converts ASCII-string to hexadecimal pattern */
uint8_t read_pattern(const char* string, uint8_t* pattern[], size_t* length)
{
    size_t  i;
    const char* current;
    char  buf[3];

    buf[2] = 0;

    *length = strlen(string);
    if (*length % 2)
        return ERR_INVALID_PARAMETER;

    *length /= 2;

    *pattern = (uint8_t*) malloc(*length);

    for (current = string, i = 0; i < *length; i++)
    {
        buf[0] = *current++;
        buf[1] = *current++;

        if (!isxdigit(buf[0]) || !isxdigit(buf[1]))
            return ERR_INVALID_PARAMETER;
        else 
            (*pattern)[i] = (uint8_t) strtoul(buf, NULL, 16);
    }

    return ERR_SUCCESS;
}

uint8_t print_version(const char* prefix, uint8_t* buffer, uint8_t* end,
                           const uint8_t* pattern, const uint32_t size, 
                           const long offset, const uint8_t end_pattern,
                           const unsigned long max_length)
{
    uint8_t *found, *terminate;
    uint8_t isFound = 0;
    
    if (!prefix || !buffer || !end || !pattern || !size || !max_length)
        return ERR_INVALID_PARAMETER;

    found = find_pattern(buffer, end, pattern, size);
//  while (found != NULL)
    {
        isFound = 1;
        terminate = find_pattern(found + offset, end, &end_pattern, 1);
        if ((unsigned long) (terminate - found - offset) > max_length)
            terminate = found + offset + max_length;
        *terminate = 0x00;
        printf("%s%s\n", prefix, found + offset);
        found = find_pattern(found + 1, end, pattern, size);
    }

    if (isFound)
        return ERR_SUCCESS;
    else
        return ERR_NOT_FOUND;
}

/* Entry point */
int main(int argc, char* argv[])

{
    FILE*    file;
    uint8_t* buffer;
    uint8_t* end;
    long filesize;
    long read;
    size_t pattern_length;
    uint8_t* pattern;
    size_t end_marker_length;
    uint8_t* end_marker_pattern;
    long offset;
    long max_length;
    uint8_t result;

    if (argc < 7)
    {
        printf("findver v0.3.2\n"
            "Prints version string found in input file\n\n"
            "Usage: findver prefix pattern offset end_marker max_length FILE\n"
            "Options:\n"
            "prefix      - Prefix string, ASCII symbols\n"
            "pattern     - Pattern to find, hex digits\n"
            "offset      - Offset of version string, integer\n"
            "end_marker  - Pattern that marks end of version string, 2 hex digits\n"
            "max_length  - Maximum length of printed version string, integer\n"
            );

        return ERR_INVALID_PARAMETER;
    }



    /* Opening file */
    file = fopen(argv[6], "rb");
    if (!file)
    {
        printf("File can't be opened.\n");
        return ERR_FILE_OPEN;
    }

    /* Determining file size */
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocating memory for buffer */
    buffer = (uint8_t*) malloc(filesize);
    if (!buffer)
    {
        printf("Can't allocate memory for file contents.\n");
        return ERR_OUT_OF_MEMORY;
    }

    /* Reading whole file to buffer */
    read = fread((void*) buffer, sizeof(char), filesize, file);
    if (read != filesize)
    {
        printf("Can't read file.\n");
        return ERR_FILE_READ;
    }

    end = buffer + filesize;

    /* Parse arguments */
        
    result = read_pattern(argv[2], &pattern, &pattern_length);
    if (result)
        return ERR_INVALID_PARAMETER;

    offset = strtol(argv[3], NULL, 10);

    result = read_pattern(argv[4], &end_marker_pattern, &end_marker_length);
    if (result)
        return ERR_INVALID_PARAMETER;
    
    max_length = strtol(argv[5], NULL, 10);

    return print_version(argv[1], buffer, end, pattern, pattern_length, offset, *end_marker_pattern, labs(max_length));
}
