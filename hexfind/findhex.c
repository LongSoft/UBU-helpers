#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define ERR_SUCCESS 0
#define ERR_NOT_FOUND 1
#define ERR_FILE_OPEN 2
#define ERR_FILE_READ 3
#define ERR_INVALID_PARAMETER 4
#define ERR_OUT_OF_MEMORY 5;

/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm
*  Returns pointer to the beginning of found pattern of NULL if not found */
uint8_t* find_pattern(uint8_t* begin, uint8_t* end, const uint8_t* pattern, size_t plen)
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

        slen     -= bad_char_skip[begin[last]];
        begin   += bad_char_skip[begin[last]];
    }

    return NULL;
}

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

/* Entry point */
int main(int argc, char* argv[])
{
    FILE*    file;
    uint8_t* buffer;
    uint8_t* end;
    uint8_t* found;
    uint8_t* pattern;
    size_t length;
    unsigned long count;
    long filesize;
    long read;
    
    if (argc < 3)
    {
        printf("hexfind v0.1.2\n\nUsage: hexfind PATTERN FILENAME\n");
        return ERR_INVALID_PARAMETER;
    }

    /* Parsing pattern string */
    if (read_pattern(argv[1], &pattern, &length))
    {
        printf("Pattern can't be parsed as hex.\n");
        return ERR_INVALID_PARAMETER;
    }

    /* Opening file */
    file = fopen(argv[2], "rb");
    if(!file)
    {
        printf("File can't be opened.\n");
        return ERR_FILE_OPEN;
    }

    /* Determining file size */
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocating memory for buffer */
    buffer = (uint8_t*)malloc(filesize);
    if (!buffer)
    {
        printf("Can't allocate memory for file contents.\n");
        return ERR_OUT_OF_MEMORY;
    }
    
    /* Reading whole file to buffer */
    read = fread((void*)buffer, sizeof(char), filesize, file);
    if (read != filesize)
    {
        printf("Can't read file.\n");
        return ERR_FILE_READ;
    }
    
    /* Searching for pattern in file and counting matches */
    count = 0;
    end = buffer + filesize;
    found = find_pattern(buffer, end, pattern, length);
    while (found)
    {
        count++;
        found = find_pattern(found + 1, end, pattern, length);
    }

    if (count)
        printf("%lu\n", count);
    else
        return ERR_NOT_FOUND;
    
    return ERR_SUCCESS;
}
