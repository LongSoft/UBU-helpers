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

/* String BIT */
const uint8_t bitx86_pattern[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x4C, 0x01
};

/* Intel GOP Driver */
/* Search pattern: "Intel (R) GOP Driver" as Unicode string */
const uint8_t snb_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x53, 0x00
};
const uint8_t ivb_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x49, 0x00
};

const uint8_t gop_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x47, 0x00, 0x4F, 0x00, 0x50, 0x00,
	0x20, 0x00, 0x44, 0x00, 0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00,
	0x72, 0x00
};

const uint8_t crv_pattern[] = {
	0x43, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x20, 0x00, 0x56, 0x00, 0x69, 0x00, 0x65, 0x00, 0x77, 0x00
};

/* Offset and length of parts of version string */
#define GOP_VERSION_2_OFFSET 0x98
#define GOP_VERSION_3_OFFSET 0xA0
#define GOP_VERSION_HSW_OFFSET 0xC0
#define GOP_VERSION_BRW_OFFSET 0xF4
#define GOP_VERSION_VLV_OFFSET 0x88
#define GOP_VERSION_CHV_OFFSET 0x88
#define GOP_VERSION_SKL_OFFSET 0xAC
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

/* AMD GOP Driver */
const uint8_t amdgop_pattern[] = {
	0x41, 0x00, 0x4D, 0x00, 0x44, 0x00, 0x20, 0x00, 0x47, 0x00, 0x4F, 0x00,
	0x50, 0x00
};

const uint8_t ms_cert_pattern[] = {
	0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x52, 0x6F,
	0x6F, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x20, 0x41,	0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79
};

#define AMDGOP1_VERSION_OFFSET 0x2E
#define AMDGOP2_VERSION_OFFSET 0x3E
#define AMDGOP_VERSION_LENGTH 0x18
#define AMDGOP_15_VERSION_LENGTH 0x14

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

/* Intel RSTe sSATA Driver */
const uint8_t 	ssata_pattern[] = {
	0x00, 0x00, 0x49, 0x00, 0x6E, 0x00 ,0x74, 0x00, 0x65, 0x00, 0x6C, 0x00,
	0x20, 0x00, 0x52, 0x00, 0x53, 0x00, 0x54, 0x00, 0x65, 0x00, 0x20, 0x00,
	0x73, 0x00, 0x53, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00, 0x20, 0x00,
	0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x72, 0x00, 0x6F, 0x00,
	0x6C, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x72, 0x00
};

/* Intel RSTe SCU Driver */
const uint8_t scu_pattern[] = {
	0x00, 0x53, 0x00, 0x43, 0x00, 0x55, 0x00
};

#define RSTE_VERSION_OFFSET 0x16
#define RSTE_VERSION_LENGTH 0x16


/* Intel RST NVMe Driver */
const uint8_t nvme_pattern[] = {
	0x4E, 0x00, 0x56, 0x00, 0x4D, 0x00, 0x65, 0x00, 0x20, 0x00, 0x55, 0x00,
	0x45, 0x00, 0x46, 0x00, 0x49, 0x00, 0x20, 0x00, 0x44, 0x00, 0x72, 0x00,
	0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00
};

#define NVME_VERSION_OFFSET 0x16
#define NVME_VERSION_LENGTH 0x14


/* AMD RAID Driver */
/* Search pattern: "AMD Raid Channel" as Unicode string */
const uint8_t amdu_pattern[] = {
	0x52, 0x00, 0x41, 0x00, 0x49, 0x00, 0x44, 0x00, 0x20, 0x00, 0x55, 0x00,
	0x74, 0x00, 0x69, 0x00, 0x6C, 0x00, 0x69, 0x00, 0x74, 0x00, 0x79, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x00, 0x52, 0x00,
	0x65, 0x00, 0x76
};

#define AMDR_VERSION_OFFSET 0x28
#define AMDR_VERSION_LENGTH 0x10

/* AMD Utility Driver */
/* Search pattern: "AMD Utility [Rev" as Unicode string */
const uint8_t amdr_pattern[] = {
	0x41, 0x00, 0x4D, 0x00, 0x44, 0x00, 0x20, 0x00, 0x52, 0x00, 0x61, 0x00,
	0x69, 0x00, 0x64, 0x00, 0x20, 0x00, 0x43, 0x00, 0x68, 0x00, 0x61, 0x00,
	0x6E, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00
};

#define AMDU_VERSION_OFFSET 0x2C
#define AMDU_VERSION_LENGTH 0x10

/* Intel LAN Driver */
/* Search pattern HEX String*/
const uint8_t lani_pattern[] = {
	0x69, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66
};
const uint8_t lanGB_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x47, 0x00, 0x69, 0x00, 0x67, 0x00,
	0x61, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x20, 0x00, 0x25, 0x00,
	0x31, 0x00, 0x64, 0x00
};
const uint8_t lan40_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x34, 0x00, 0x30, 0x00, 0x47, 0x00,
	0x62, 0x00, 0x45, 0x00
};
const uint8_t lan10_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x47, 0x00,
	0x62, 0x00, 0x45, 0x00, 0x20, 0x00, 0x44, 0x00, 0x72, 0x00, 0x69, 0x00,
	0x76, 0x00, 0x65, 0x00, 0x72, 0x00
};
const uint8_t lans_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x50, 0x00, 0x52, 0x00, 0x4F, 0x00,
	0x2F, 0x00, 0x31, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00,
	0x47
};

const uint8_t fcoe_pattern[] = {
	0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x28, 0x00,
	0x52, 0x00, 0x29, 0x00, 0x20, 0x00, 0x46, 0x00, 0x43, 0x00, 0x6F, 0x00,
	0x45, 0x00, 0x20, 0x00, 0x42, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00,
	0x20, 0x00, 0x4E, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00,
	0x65, 0x00, 0x20, 0x00, 0x55, 0x00, 0x45, 0x00, 0x46, 0x00, 0x49, 0x00,
	0x20, 0x00, 0x44, 0x00, 0x72, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x20, 0x00, 0x76, 0x00
};

const uint8_t fcoeh_pattern[] = {
	0xAC, 0xB6, 0xB4, 0xB6, 0x76, 0xB1, 0x5E, 0x80
};

#define LANI_VERSION_4_OFFSET 0x32
#define LANI_VERSION_5_OFFSET 0x22
#define LANI_VERSION_LENGTH 0x3
#define FCOE_VERSION_OFFSET 0x4E
#define FCOE_VERSION_LENGTH 0x12

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
	0x20, 0x00, 0x52, 0x00, 0x41, 0x00, 0x49, 0x00, 0x44, 0x00, 0x20
};

#define MSATA_VERSION_OFFSET 56
#define MSATA_VERSION_LENGTH 0x4

/* Realtek LAN Driver */
/* Search pattern HEX String*/
const uint8_t lanrtk_pattern[] = {
	0x52, 0x00, 0x65, 0x00, 0x61, 0x00, 0x6C, 0x00,
	0x74, 0x00, 0x65, 0x00, 0x6B, 0x00, 0x20, 0x00,
	0x55, 0x00, 0x45, 0x00, 0x46, 0x00, 0x49, 0x00,
	0x20, 0x00, 0x55, 0x00, 0x4E, 0x00, 0x44, 0x00,
	0x49, 0x00, 0x20, 0x00, 0x44, 0x00, 0x72, 0x00,
	0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00
};
const uint8_t lanr_new_pattern[] = {
	0x01, 0xB2, 0x38, 0x78, 0x81, 0x43, 0x9B, 0x43
};
const uint8_t lanr_old_pattern[] = {
	0x04, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00
};

/* Broadcom LAN Driver */
/* Search pattern HEX String*/
const uint8_t lanb_pattern[] = {
	0x55, 0x4E, 0x44, 0x49, 0x5F, 0x56, 0x45, 0x52
};

#define LANB_VERSION_14_OFFSET 0x11A
#define LANB_VERSION_15_OFFSET 0x12A
#define LANB_VERSION_16_OFFSET 0x16A
#define LANB_VERSION_16_1_OFFSET 0x1CA
#define LANB_VERSION_LENGTH 0x3

/* Intel CPU Microcode */
/* Search pattern HEX String*/
const uint8_t icpuskls_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xE3, 0x06, 0x05, 0x00, 0x00, 0x00
};
const uint8_t icpuhe_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xF2, 0x06, 0x03, 0x00, 0x00, 0x00
};
const uint8_t icpub_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0x71, 0x06, 0x04, 0x00, 0x00, 0x00
};
const uint8_t icpuh_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xC3, 0x06, 0x03, 0x00, 0x00, 0x00
};
const uint8_t icpui_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xA9, 0x06, 0x03, 0x00, 0x00, 0x00
};
const uint8_t icpus_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xA7, 0x06, 0x02, 0x00, 0x00, 0x00
};
const uint8_t icpusnbe6_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xD6, 0x06, 0x02, 0x00, 0x00, 0x00
};
const uint8_t icpusnbe_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xD7, 0x06, 0x02, 0x00, 0x00, 0x00
};
const uint8_t icpuivbe_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xE4, 0x06, 0x03, 0x00, 0x00, 0x00
};
const uint8_t icpuivbe7_pattern[] = {
	0x01, 0x00, 0x00, 0x00, 0xE7, 0x06, 0x03, 0x00, 0x00, 0x00
};

#define CPU_VERSION_OFFSET 0x4C
#define CPU_VERSION_LENGTH 0x1

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
	wchar_t* build;
    long filesize;
    long read;
	char *strb;
	char mnr;
    
    if (argc < 2)
    {
        printf("drvver v0.19.10\n");
        printf("Reads versions from input EFI-file\n");
        printf("Usage: drvver DRIVERFILE\n\n");
        printf("Support:\n"
		"GOP driver Intel, AMD, ASPEED.\n"
		"SATA driver Intel, AMD, Marvell\n"
		"LAN driver Intel, Realtek, Broadcom\n"
		);
        return ERR_INVALID_PARAMETER;
    }

    /* Opening file */
    file = fopen(argv[1], "rb");
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
	if (find_pattern(buffer, end, bitx86_pattern, sizeof(bitx86_pattern)))
		strb=" x86";
	else
		strb="";

    found = find_pattern(buffer, end, gop_pattern, sizeof(gop_pattern));
    if (found)
	{
		/* Checking for version 2 */
		if (find_pattern(buffer, end, snb_pattern, sizeof(snb_pattern)))
		{
		check = found + GOP_VERSION_2_OFFSET;
		if ((check[0] == '2') || (check[0] == 'C'))
		{
			check += GOP_MAJOR_LENGTH;
			check += GOP_MINOR_LENGTH;
			if ((check[2] == 0x2E) || (check[2] == 0x00) || (check[10] != 0x00))
				check += GOP_REVISION_LENGTH;
			if (check[0] == 'L') 
				check -= 0x20;
			build = (wchar_t*) check;
			/* Printing the version found */
			wprintf(L"     EFI GOP Driver SandyBridge - 2.0.%s\n", build);

			return ERR_SUCCESS; 
		}
		}
	
		/* Checking for version 3 */
		if (find_pattern(buffer, end, ivb_pattern, sizeof(ivb_pattern)))
		{
		check = found + GOP_VERSION_3_OFFSET;
		if ((check[0] == '3') || (check[0] == 'L'))
		{
			check += GOP_MAJOR_LENGTH;
			check += GOP_MINOR_LENGTH;
			if ((check[2] == 0x2E) || (check[2] == 0x00) || (check[10] != 0x00))
				check += GOP_REVISION_LENGTH;
			if (check[0] == 0x45)
				check -= 0x30;
			build = (wchar_t*) check;
			/* Printing the version found */
			wprintf(L"     EFI GOP Driver IvyBridge   - 3.0.%s\n", build);

			return ERR_SUCCESS; 
		}
		}

		/* Checking for version 5 Haswell*/
		check = found + GOP_VERSION_HSW_OFFSET;
		if ((check[0] == '5') || (check[0] == 'H') || ((check[0] == 0x06) && (check[1] == 0x0A)))
			{
			check += GOP_MAJOR_LENGTH; 
			check += GOP_MINOR_LENGTH; 
			if (check[-2] == 'I')
	 			check -= 0x48;
			else if ((check[0] == 0x1A) && (check[1] == 0x0A) && (check[40] == '5'))
	 			check = check + 56;
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver Haswell     - 5.0.%s\n", build);

		return ERR_SUCCESS;

		}

		/* Checking for version 5.5 Broadwell*/
		check = found + GOP_VERSION_BRW_OFFSET;
		if (check[0] == '5')
		{
			check += GOP_MAJOR_LENGTH;
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver Broadwell   - 5.5.%s\n", build);

			return ERR_SUCCESS; 
		}

		/* Checking for version 6 CloverView*/
		if (find_pattern(buffer, end, crv_pattern, sizeof(crv_pattern)))
		{
		check = found;
		if ((check[-28] == '6') && (check[-26] == '.') && (check[-24] == '0'))
			check -= 0x28;
		if ((check[-40] == '6') && (check[-38] == '.') && (check[-36] == '0'))
			check += 0x80;

		build = (wchar_t*) check;

		/* Printing the version found */
		wprintf(L"     EFI GOP Driver CloverView  - 6.0.%s%S\n", build, strb);

			return ERR_SUCCESS; 
		}

		/* Checking for version ValleyView*/
		check = found + GOP_VERSION_VLV_OFFSET;
		if (check[0] == '7')
		{
		if ((check[4] == '0') && (check[8] == '1'))
		{	mnr = '0';
			check = check + 8;}
		else if (((check[4] == '1') && (check[8] == '1')) ||
			((check[4] == 0x00) && (check[8] == '1') && (check[20] == 0xFF)))
		{	mnr = '1';
			check = check + 8;}
		else if ((check[4] == '1') && (check[16] == 0xFF))
		{	mnr = '1';
			check = check + 4;}
		else if (((check[4] == '2') && (check[8] == '1')) ||
			((check[4] == 0x00) && (check[8] == '1') && (check[20] == 0x00)))
		{	mnr = '2';
			check = check + 8;}
		else if ((check[4] == '1') && (check[16] == 0x00))
		{	mnr = '2';
			check = check + 4;}

                 	build = (wchar_t*) check;
			wprintf(L"     EFI GOP Driver ValleyView  - 7.%c.%s%S\n", mnr, build, strb);
			return ERR_SUCCESS; 
		}

		/* Checking for version 8 CherryView*/
		check = found + GOP_VERSION_CHV_OFFSET;
		if (check[0] == '8')
		{
		if (check[4] != '1')
		{
			check += 0x4;
		}
			check += GOP_MAJOR_LENGTH;
			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver CherryView  - 8.0.%s\n", build);

			return ERR_SUCCESS; 
		}

		/* Checking for version 9 SkyLake*/
		check = found + GOP_VERSION_SKL_OFFSET;
		{
		if (((check[0] == '9') && (check[4] == '1')) ||
		   ((check[-4] == '9') && (check[4] == '1')))
			check += 4;
		else if ((check[8] == '9') && (check[12] == '1'))
			check += 12;
		else if ((check[52] == '9') && (check[56] == '0') && (check[60] == '1'))
			check += 60;

			build = (wchar_t*) check;

			/* Printing the version found */
			wprintf(L"     EFI GOP Driver SkyLake     - 9.0.%s\n", build);

			return ERR_SUCCESS; 
		}

		/* Unknown version */
		printf ("     Unknown version GOP Driver\n");
		return ERR_UNKNOWN_VERSION;
	}

	/* Searching for AMD GOP pattern in file */
	found = find_pattern(buffer, end, amdgop_pattern, sizeof(amdgop_pattern));
	if (found)
	{
		check = found;
       		if ((check[46] == '1') && (check[66] == '.'))
		{
			found += AMDGOP1_VERSION_OFFSET;
			build = (wchar_t*) found;
			build[AMDGOP_15_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		}
		else if ((check[46] == '1') && (check[66] != '.'))
		{
			found += AMDGOP1_VERSION_OFFSET;
			build = (wchar_t*) found;
			build[AMDGOP_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		}
                else if ((check[46] == 'v') && (check[82] == '.'))
		{
			found += AMDGOP2_VERSION_OFFSET;
			build = (wchar_t*) found;
			build[AMDGOP_15_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		}
                else
		{
			found += AMDGOP2_VERSION_OFFSET;
			build = (wchar_t*) found;
			build[AMDGOP_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		}

		/* Printing the version found */
		if (find_pattern(buffer, end, ms_cert_pattern, sizeof(ms_cert_pattern)))
			wprintf(L"     EFI AMD GOP Driver         - %s_signed\n", build);
		else
			wprintf(L"     EFI AMD GOP Driver         - %s\n", build);

		return ERR_SUCCESS; 
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
		wprintf(L"     EFI IRST RAID for SATA     - %s\n", build);

		return ERR_SUCCESS; 
	}

	/* Searching for NVMe pattern in file */
	found = find_pattern(buffer, end, nvme_pattern, sizeof(nvme_pattern));
	if (found)
	{
		found -= NVME_VERSION_OFFSET;
		build = (wchar_t*) found;
		build[NVME_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
		wprintf(L"     EFI IRST NVMe Driver       - %s\n", build);

		return ERR_SUCCESS; 
	}

	/* Searching for AMD RAID pattern in file */
	found = find_pattern(buffer, end, amdr_pattern, sizeof(amdr_pattern));
	if (found)
	{
		found += AMDR_VERSION_OFFSET;
		build = (wchar_t*) found;
		build[AMDR_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
		wprintf(L"     EFI AMD RAID               - %s\n", build);

		return ERR_SUCCESS; 
	}

	/* Searching for AMD Utilty pattern in file */
	found = find_pattern(buffer, end, amdu_pattern, sizeof(amdu_pattern));
	if (found)
	{
		check = found;
	        found += AMDU_VERSION_OFFSET;
		build = (wchar_t*) found;
		build[AMDU_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
		if (check[52] != ']')
		wprintf(L"     EFI AMD Utility            - %s\n", build);
		else
		printf ("     EFI AMD Utility            - %c.0.0.%c%c\n", check[44], check[48], check[50]);
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
		if (find_pattern(buffer, end, scu_pattern, sizeof(scu_pattern)))
			wprintf(L"     EFI IRSTe RAID for SCU     - %s\n", build);
		else 
			if (find_pattern(buffer, end, ssata_pattern, sizeof(ssata_pattern)))
				wprintf(L"     EFI IRSTe RAID for sSATA   - %s\n", build);
			else
				wprintf(L"     EFI IRSTe RAID for SATA    - %s\n", build);
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
        else if (found[LANI_VERSION_5_OFFSET] == 3 || found[LANI_VERSION_5_OFFSET] == 4 ||
		 found[LANI_VERSION_5_OFFSET] == 5 || found[LANI_VERSION_5_OFFSET] == 6 ||
		 ((found[LANI_VERSION_5_OFFSET-3]  == 0) && (found[LANI_VERSION_5_OFFSET-2]  == 1) &&
		 (found[LANI_VERSION_5_OFFSET-1]  == 0) && (found[LANI_VERSION_5_OFFSET]  == 0) &&
		 (found[LANI_VERSION_5_OFFSET+1]  == 0) && (found[LANI_VERSION_5_OFFSET+30]  == 0x2F)) || 
		found[LANI_VERSION_5_OFFSET]  != 0)
                check = found + LANI_VERSION_5_OFFSET;
	else if (find_pattern(buffer, end, lanGB_pattern, sizeof(lanGB_pattern)))
		{
		if (found[LANI_VERSION_5_OFFSET] == 0)
		check = found + LANI_VERSION_5_OFFSET;
		}
        else if (find_pattern(buffer, end, lan40_pattern, sizeof(lan40_pattern)))
		{
		if (found[LANI_VERSION_5_OFFSET] == 0)
            	check = found - 30;
		}
        else {
            printf("     Unknown Intel LAN version.\n");
            return ERR_NOT_FOUND;
        }

        /* Printing the version found */

		if (find_pattern(buffer, end, lan40_pattern, sizeof(lan40_pattern)))
			printf("     EFI Intel 40GbE UNDI       - %x.%x.%02x\n", check[0], check[-1], check[-2]);
		else if (find_pattern(buffer, end, lan10_pattern, sizeof(lan10_pattern)))
			printf("     EFI Intel 10GbE UNDI       - %x.%x.%02x\n", check[0], check[-1], check[-2]);
		else if (find_pattern(buffer, end, lans_pattern, sizeof(lans_pattern)))
			printf("     EFI Intel PRO/Server UNDI  - %x.%x.%02x\n", check[0], check[-1], check[-2]);
		else if (find_pattern(buffer, end, lanGB_pattern, sizeof(lanGB_pattern)))
			printf("     EFI Intel Gigabit UNDI     - %x.%x.%02x\n", check[0], check[-1], check[-2]);
		else
			printf("     EFI Intel PRO/1000 UNDI    - %x.%x.%02x\n", check[0], check[-1], check[-2]);

		return ERR_SUCCESS; 
    }

	/* Searching for FCoE pattern in file */
	found = find_pattern(buffer, end, fcoe_pattern, sizeof(fcoe_pattern));
	if (found)
	{
		found += FCOE_VERSION_OFFSET;
		check = (found);
		if (check[0] == '1')
		{
			build = (wchar_t*) found;
			build[FCOE_VERSION_LENGTH/sizeof(wchar_t)] = 0x00;
		/* Printing the version found */
			wprintf(L"     EFI Intel FCoE Boot        - %s\n", build);
			return ERR_SUCCESS; 
		}
		else if (find_pattern(buffer, end, fcoeh_pattern, sizeof(fcoeh_pattern)))
		{
			check = (find_pattern(buffer, end, fcoeh_pattern, sizeof(fcoeh_pattern))) + 35;
			if (check[0] == 1)
			{
				printf("     EFI Intel FCoE Boot        - %d.%d.%02d\n", check[0], check[-1],check[-2]);
				return ERR_SUCCESS;}
		}
		printf("     Unknown Intel FCoE version.\n");
		return ERR_NOT_FOUND;
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
        else if (found[LANB_VERSION_16_1_OFFSET] == 16)
            check = found + LANB_VERSION_16_1_OFFSET;
        else {
            printf("     Unknown Broadcom LAN version.\n");
            return ERR_NOT_FOUND;
        }
        /* Printing the version found */
	printf("     EFI Broadcom UNDI          - %d.%d.%d\n", check[0], check[-1], check[-2]);
	return ERR_SUCCESS; 
   }

	/* Searching for LAN Realtek pattern in new file */
   found = find_pattern(buffer, end, lanrtk_pattern, sizeof(lanrtk_pattern));
   if (found)
   {
	if (find_pattern(buffer, end, lanr_new_pattern, sizeof(lanr_new_pattern)))
	{
	check = find_pattern(buffer, end, lanr_new_pattern, sizeof(lanr_new_pattern));
		if (check[-22] == 0x20)
			check = check - 22;
		else if ((check[-23] == 0x20) || (check[-23] == 0x30))
			check = check - 23;
		else if (check[-11] == 0x20)
			check = check - 11;
	 	else {
		printf("     Unknown Realtek LAN version.\n");
		return ERR_NOT_FOUND;}
	}

	else if (find_pattern(buffer, end, lanr_old_pattern, sizeof(lanr_old_pattern)))
	{
	check = find_pattern(buffer, end, lanr_old_pattern, sizeof(lanr_old_pattern));
		if ((check[-30] == 0x20) || (check[-30] != 0x2F)  || 
		    (check[-29] != 0x00) || (check[-31] == 0x00))
			check = check - 30;
		else if (check[-18] == 0x20)
			check = check - 18;
	 	else {
			printf("     Unknown Realtek LAN version.\n");
		return ERR_NOT_FOUND;}
	}

	/* Printing the version found */
	if (check[-2] != 0) {
		printf("     EFI Realtek UNDI           - %x.%03X %X%s\n", check[0] >> 4, check[-1], check[-2], strb);
        	return ERR_SUCCESS;}
	else {
		printf("     EFI Realtek UNDI           - %x.%03X%s\n", check[0] >> 4, check[-1], strb);
        	return ERR_SUCCESS;}



   }

	/* Searching for CPU pattern LGA1150 */
   found = find_pattern(buffer, end, icpub_pattern, sizeof(icpub_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 040671 BDW   - %02X\n", check[0]);
   }
   found = find_pattern(buffer, end, icpuh_pattern, sizeof(icpuh_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0306C3 HSW   - %02X\n", check[0]);
       	return ERR_SUCCESS;
   }

	/* Searching for CPU pattern LGA1155 */
   found = find_pattern(buffer, end, icpui_pattern, sizeof(icpui_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0306A9 IVB   - %02X\n", check[0]);
   }
   found = find_pattern(buffer, end, icpus_pattern, sizeof(icpus_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0206A7 SNB   - %02X\n", check[0]);
       	return ERR_SUCCESS;
   }
 
	/* Searching for CPU pattern LGA2011 */
   found = find_pattern(buffer, end, icpuivbe7_pattern, sizeof(icpuivbe7_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0306E7 IVB-E - %X%02X\n", check[1], check[0]);
   }
   found = find_pattern(buffer, end, icpuivbe_pattern, sizeof(icpuivbe_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0306E4 IVB-E - %X%02X\n", check[1], check[0]);
   }
   found = find_pattern(buffer, end, icpusnbe_pattern, sizeof(icpusnbe_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0206D7 SNB-E - %X%02X\n", check[1], check[0]);
   }
   found = find_pattern(buffer, end, icpusnbe6_pattern, sizeof(icpusnbe6_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0206D6 SNB-E - %X%02X\n", check[1], check[0]);
       	return ERR_SUCCESS;
   }

	/* Searching for CPU pattern LGA2011v3 */
   found = find_pattern(buffer, end, icpuhe_pattern, sizeof(icpuhe_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0306F2 HSW-E - %02X\n", check[0]);
       	return ERR_SUCCESS;
   }

	/* Searching for CPU pattern LGA1151 */
   found = find_pattern(buffer, end, icpuskls_pattern, sizeof(icpuskls_pattern));
   if (found)
   {
	check = found - CPU_VERSION_OFFSET;
	printf("     CPU Microcode 0506E3 SKL-S - %02X\n", check[0]);
       	return ERR_SUCCESS;
   }

  return ERR_NOT_FOUND;
}
