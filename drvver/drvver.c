#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <wchar.h>

/* Return codes */
#define ERR_SUCCESS 0
#define ERR_NOT_FOUND 1
#define ERR_FILE_OPEN 2
#define ERR_FILE_READ 3
#define ERR_INVALID_PARAMETER 4
#define ERR_OUT_OF_MEMORY 5
#define ERR_UNKNOWN_VERSION 6

/* Intel GOP Driver */
/* Search pattern: "Intel (R) GOP Driver" as Unicode string */
const uint8_t gop_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x47, 0x00, 0x4F, 0x00, 0x50, 0x00,
	0x20, 0x00, 0x44, 0x00, 0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00,
	0x72, 0x00
};

/* Offset and length of parts of version string */
#define GOP_VERSION_2_OFFSET 0x98
#define GOP_VERSION_3_OFFSET 0xA0
#define GOP_VERSION_HSW_OFFSET 0xC0
#define GOP_VERSION_BRW_OFFSET 0xF4
#define GOP_MAJOR_LENGTH 4
#define GOP_MINOR_LENGTH 4
#define GOP_REVISION_LENGTH 8
#define GOP_BUILD_LENGTH 10

/* ASPEED GOP Driver */
/* Search pattern hwx string */
const uint8_t gop_ast_pattern[] = {
	0x0F, 0x10, 0x0B, 0x0D, 0x10, 0x0B, 0x0C, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};
const uint8_t goprom_ast_pattern[] = {
	0x00, 0x50, 0x43, 0x49, 0x52
};


/* Offset and length of parts of version string */
#define GOP_AST_VERSION_OFFSET 57
#define GOP_AST_VERSION_LENGTH 0x3

/* Intel RST Driver */
/* Search pattern: "Intel (R) RST 1" as Unicode string */
const uint8_t rst_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x52, 0x00, 0x53, 0x00, 0x54, 0x00,
	0x20, 0x00, 0x31, 0x00
};

/* Offset and length of parts of version string */
#define RST_VERSION_OFFSET 0x1A
#define RST_VERSION_LENGTH 0x16

/* Intel RSTe Driver */
/* Search pattern: "Intel (R) RSTe " as Unicode string */
const uint8_t rste_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x20, 0x00,
	0x52, 0x00, 0x53, 0x00, 0x54, 0x00, 0x65, 0x00, 0x20, 0x00
};

#define RSTE_VERSION_OFFSET 0x16
#define RSTE_VERSION_LENGTH 0x16

/* Intel LAN Driver */
/* Search pattern HEX String*/
const uint8_t lani_pattern[] = {
	0x20, 0x0C, 0x9A, 0x66
};

#define LANI_VERSION_4_OFFSET 0x2F
#define LANI_VERSION_5_OFFSET 0x1F
#define LANI_VERSION_LENGTH 0x3

/* Marwell SATA Driver */
/* Search pattern is "Marwell Connection" as Unicode string */
const uint8_t msata_pattern[] = {
    0x4D, 0x00, 0x61, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x6C, 0x00, 
    0x6C, 0x00, 0x20, 0x00, 0x43, 0x00, 0x68, 0x00, 0x61, 0x00, 0x6E, 0x00, 
    0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00
};
/* Marwell RAID Driver */
/* Search pattern is "Marwell Connection" as Unicode string */
const uint8_t msatar_pattern[] = {
    0x4D, 0x41, 0x52, 0x56, 0x45, 0x4C, 0x4C, 0x20, 0x52, 0x61, 0x69, 0x64
};

#define MSATA_VERSION_OFFSET 56
#define MSATA_VERSION_LENGTH 0x4

/* Realtek LAN Driver */
/* Search pattern HEX String*/
const uint8_t lanr_new_pattern[] = {
	0x01, 0xB2, 0x38, 0x78, 0x81, 0x43, 0x9B, 0x43
};
const uint8_t lanr_old_pattern[] = {
	0x04, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00
};

#define LANR_VERSION_NEW_OFFSET 0x17
#define LANR_VERSION_OLD_OFFSET 0x1E
#define LANR_VERSION_LENGTH 0x3

/* Broadcom LAN Driver */
/* Search pattern HEX String*/
const uint8_t lanb_pattern[] = {
	0x55, 0x4E, 0x44, 0x49, 0x5F, 0x56, 0x45, 0x52
};

#define LANB_VERSION_14_OFFSET 0x11A
#define LANB_VERSION_15_OFFSET 0x12A
#define LANB_VERSION_16_OFFSET 0x16A
#define LANB_VERSION_LENGTH 0x3

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

/* Entry point */
int main(int argc, char* argv[])
{
    FILE*    file;
    uint8_t* buffer;
    uint8_t* end;
    uint8_t* found;
	uint8_t* check;
	wchar_t* minor;
	wchar_t* build;
    long filesize;
    long read;
	char has_rev;
    
    if (argc < 2)
    {
        printf("drvver v0.9\n");
        printf("Reads versions from input EFI-file\n");
        printf("Usage: drvver DRIVERFILE\n\n");
        printf("Support:\n"
		"GOP driver Intel, ASPEED.\n"
		"SATA driver Intel Marvell\n"
		"LAN driver Intel, Realtek, Broadcom\n"
		);
        return ERR_INVALID_PARAMETER;
    }

    /* Opening file */
    file = fopen(argv[1], "r+b");
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

    
    /* Searching for GOP pattern in file */
    end = buffer + filesize - 1;
    found = find_pattern(buffer, end, gop_pattern, sizeof(gop_pattern));
    if (found)
	{
		/* Checking for version 2 */
		check = found + GOP_VERSION_2_OFFSET;
		if (check[0] == '2')
		{
			has_rev = (check[2] == 0x2E);
			check += GOP_MAJOR_LENGTH;
			minor = (wchar_t*) check;
			check += GOP_MINOR_LENGTH;
			if (has_rev)
			{
				//revision = (wchar_t*) check;
				check += GOP_REVISION_LENGTH;
			}
			//else
			//	revision = L"0";
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver SandyBridge - 2.%s.%s\n", minor, build);

			return ERR_SUCCESS; 
		}
	
		/* Checking for version 3 */
		check = found + GOP_VERSION_3_OFFSET;
		if (check[0] == '3')
		{
			has_rev = (check[2] == 0x2E);
			check += GOP_MAJOR_LENGTH;
			minor = (wchar_t*) check;
			check += GOP_MINOR_LENGTH;
			if (has_rev)
			{
				//revision = (wchar_t*) check;
				check += GOP_REVISION_LENGTH;
			}
			//else
			//	revision = L"0";
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver IvyBridge   - 3.%s.%s\n", minor, build);

			return ERR_SUCCESS; 
		}

		/* Checking for version 5 Haswell*/
		check = found + GOP_VERSION_HSW_OFFSET;
		if (check[0] == '5')
		{
			check += GOP_MAJOR_LENGTH;
			minor = (wchar_t*) check;
			check += GOP_MINOR_LENGTH;
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver Haswell     - 5.%s.%s\n", minor, build);

			return ERR_SUCCESS; 
		}

		/* Checking for version 5 Broadwell*/
		check = found + GOP_VERSION_BRW_OFFSET;
		if (check[0] == '5')
		{
			check += GOP_MAJOR_LENGTH;
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver Broadwell   - 5.%s\n", build);

			return ERR_SUCCESS; 
		}

		/* Unknown version */
		return ERR_UNKNOWN_VERSION;
	}

	/* Searching for ASPEED GOP pattern in file */
	found = find_pattern(buffer, end, gop_ast_pattern, sizeof(gop_ast_pattern));
	if (found)
	{
		if ((found[GOP_AST_VERSION_OFFSET] == 37))
			{check = found + GOP_AST_VERSION_OFFSET; check[-1] = 0x08; check[0] = 0x93; check[1] = 0x00;}
		else if ((found[GOP_AST_VERSION_OFFSET] == 33))
			{check = found + GOP_AST_VERSION_OFFSET; check[-1] = 0x00; check[0] = 0x96; check[1] = 0x00;}
		else if ((found[GOP_AST_VERSION_OFFSET] == 144))
			{check = found + GOP_AST_VERSION_OFFSET; check[-1] = 0x06; check[0] = 0x97; check[1] = 0x00;}
		else
		check = found + GOP_AST_VERSION_OFFSET;

        /* Printing the version found */
	found = find_pattern(buffer, end, goprom_ast_pattern, sizeof(goprom_ast_pattern));
	if (found)
		printf("     EFI GOP-in-OROM ASPEED     - %x.%02x.%02x\n", check[+1], check[0], check[-1]);
	else
		printf("     EFI GOP ASPEED             - %x.%02x.%02x\n", check[+1], check[0], check[-1]);

        return ERR_SUCCESS;
    }

	/* Searching for RST pattern in file */
	found = find_pattern(buffer, end, rst_pattern, sizeof(rst_pattern));
	if (found)
	{
		found += RST_VERSION_OFFSET;
		build = (wchar_t*) found;
		build[RST_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
		wprintf(L"     EFI IRST SATA              - %s\n", build);

		return ERR_SUCCESS; 
	}

	/* Searching for RSTe pattern in file */
	found = find_pattern(buffer, end, rste_pattern, sizeof(rste_pattern));
	if (found)
	{
		found += RSTE_VERSION_OFFSET;
		build = (wchar_t*) found;
		build[RSTE_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
		wprintf(L"     EFI IRSTe SATA             - %s\n", build);

		return ERR_SUCCESS; 
	}

    /* Searching for MSATA pattern in file */
    found = find_pattern(buffer, end, msata_pattern, sizeof(msata_pattern));
    if (found)
    {
        check = found + MSATA_VERSION_OFFSET;

        /* Printing the version found */
		found = find_pattern(buffer, end, msatar_pattern, sizeof(msatar_pattern));
		if (found)
		printf("     EFI Marvell SATA RAID      - %x.%x.%x.%04x\n", (check[3] >> 4), (check[3] & 0x0F), check[2], *(uint16_t*)check);
		else
		printf("     EFI Marvell SATA AHCI      - %x.%x.%x.%04x\n", (check[3] >> 4), (check[3] & 0x0F), check[2], *(uint16_t*)check);

        return ERR_SUCCESS;
    }

	/* Searching for LANI pattern in file */
    found = find_pattern(buffer, end, lani_pattern, sizeof(lani_pattern));
    if (found)
    {
		/* Checking for version 4 */
        if (found[LANI_VERSION_4_OFFSET] == 4)
            check = found + LANI_VERSION_4_OFFSET;
		/* Checking for version 5 or 6 */
        else if (found[LANI_VERSION_5_OFFSET] == 5 || found[LANI_VERSION_5_OFFSET] == 6)
            check = found + LANI_VERSION_5_OFFSET;
        else {
            printf("     Unknown Intel LAN version.\n");
            return ERR_NOT_FOUND;
        }

        /* Printing the version found */
		printf("     EFI Intel UNDI             - %x.%x.%02x\n", check[0], check[-1], check[-2]);

		return ERR_SUCCESS; 
    }

	/* Searching for LANB pattern in file */
   found = find_pattern(buffer, end, lanb_pattern, sizeof(lanb_pattern));
   if (found)
   {
		/* Checking for version 14 */
        if (found[LANB_VERSION_14_OFFSET] == 14)
            check = found + LANB_VERSION_14_OFFSET;
		/* Checking for version 15 */
        else if (found[LANB_VERSION_15_OFFSET] == 15)
            check = found + LANB_VERSION_15_OFFSET;
		/* Checking for version 16 */
        else if (found[LANB_VERSION_16_OFFSET] == 16)
            check = found + LANB_VERSION_16_OFFSET;
        else {
            printf("     Unknown Broadcom LAN version.\n");
            return ERR_NOT_FOUND;
        }

        /* Printing the version found */
		printf("     EFI Broadcom UNDI          - %d.%d.%d\n", check[0], check[-1], check[-2]);

		return ERR_SUCCESS; 
   }

	/* Searching for LANR pattern in new file */
   found = find_pattern(buffer, end, lanr_new_pattern, sizeof(lanr_new_pattern));
   if (found)
   {
		if ((found[LANR_VERSION_NEW_OFFSET] == 4) || (found[LANR_VERSION_NEW_OFFSET] == 0))
		check = found - LANR_VERSION_NEW_OFFSET;
 	else {
		printf("     Unknown Realtek LAN version.\n");
		return ERR_NOT_FOUND;}

	/* Printing the version found */
	if (check[+1] != 0) {
		printf("     EFI Realtek UNDI           - %x.%03x %X\n", check[+1] >> 4, check[0], check[-1]);
        	return ERR_SUCCESS;}
	else {
		printf("     EFI Realtek UNDI           - %x.%03X\n", check[0] >> 4, check[-1]);
        	return ERR_SUCCESS;}
   }

	/* Searching for LANR pattern in old file */
   found = find_pattern(buffer, end, lanr_old_pattern, sizeof(lanr_old_pattern));
   if (found)
   {
		if (found[LANR_VERSION_OLD_OFFSET] == 0)
		check = found - LANR_VERSION_OLD_OFFSET;
 	else {
		printf("     Unknown Realtek LAN version.\n");
		return ERR_NOT_FOUND;}

	/* Printing the version found */
	if (check[+1] != 0) {
		printf("     EFI Realtek UNDI           - %x.%03x %X\n", check[+1] >> 4, check[0], check[-1]);
        	return ERR_SUCCESS;}
	else {
		printf("     EFI Realtek UNDI           - %x.%03X\n", check[0] >> 4, check[-1]);
        	return ERR_SUCCESS;}
   }
   return ERR_NOT_FOUND;
}
