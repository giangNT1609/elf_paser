#include <iostream>
#include <inttypes.h> // PRIx64 
#include "../elf_parser.hpp"
#include "libelf.h"

void print_elf_header64(Elf64_Ehdr elf_header);
void printHeader(Elf64_Ehdr elf_header);

int main(int argc, char* argv[]) {
    char usage_banner[] = "usage: ./header [<executable>]\n";
    if(argc < 2) {
        std::cerr << usage_banner;
        return -1;
    }

    std::string program((std::string)argv[1]);
    elf_parser::Elf_parser elf_parser(program);

    std::vector<elf_parser::elf_header> header = elf_parser.get_elfHeader();
    //print_header(header);
    //print_elf_header64(header[0].elfHeader);
	Elf64_Ehdr tmp = header[0].elfHeader;
	printHeader(tmp);
    return 0;
}

//decode:
const char *sys_name(uint8_t sys) {
    switch (sys) {
    case 0x00: return "SYSTEM V";
    case 0x01: return "HP-UX";
    case 0x02: return "NET BSD";
    case 0x03: return "Linux";
    case 0x04: return "HP-UX";
    case 0x05: return "GNU Hurd";
    case 0x06: return "Solaris";
    case 0x07: return "AIX";
    case 0x08: return "IRIX";
    case 0x09: return "FreeBSD";
    case 0x0A: return "TRU64";
    case 0x0B: return "Novell Modesto";
    case 0x0C: return "OpenBSD";
    case 0x0D: return "OpenVMS";
    case 0x0E: return "NonStop Kernel";
    case 0x0F: return "AROS";
    case 0x10: return "Fenix OS";
    case 0x11: return "CloudABI";
    case 0x12: return "Stratus Technologies OpenVOS";
    }
    return "Unknown";
}
  
const char *type_name(uint16_t type) {
    switch (type) {
    case 0x00:   return "NONE";
    case 0x01:   return "REL";
    case 0x02:   return "EXEC";
    case 0x03:   return "DYN";
    case 0x04:   return "CORE";
    case 0xFE00: return "LOOS";
    case 0xFEFF: return "HIOS";
    case 0xFF00: return "LOPROC";
    case 0xFFFF: return "HIPROC";
    }
    return "Unknown";
}
  
const char *machine_name(uint16_t machine) {
    switch (machine) {
    case 0x00: return "No specific instruction set";
    case 0x01: return "AT&T WE 32100";
    case 0x02: return "SPARC";
    case 0x03: return "x86";
    case 0x04: return "Motorola 68000k (M68k)";
    case 0x05: return "Motorola 88000 (M88k)";
    case 0x06: return "Intel MCU";
    case 0x07: return "Intel 80860";
    case 0x08: return "MIPS";
    case 0x09: return "IBM_System/370";
    case 0x0A: return "MIPS RS3000 Little-endian";
    case 0x0B: return "Reserved for future use";
    case 0x0C: return "Reserved for future use";
    case 0x0D: return "Reserved for future use";
    case 0x0E: return "Hewlett-Packard PA-RISC";
    case 0x0F: return "Reserved for future use";
    case 0x13: return "Intel 80960";
    case 0x14: return "PowerPC";
    case 0x15: return "PowerPC(64-bit)";
    case 0x16: return "S390, including S390x";
    case 0x28: return "ARM (up to ARMv7/Aarch32)";
    case 0x2A: return "SuperH";
    case 0x32: return "IA-64";
    case 0x3E: return "amd64";
    case 0x8C: return "TMS320C6000 Family";
    case 0xB7: return "ARM 64-bits (ARMv8/Aarch64)";
    case 0xF3: return "RISC-V";
    case 0xF7: return "Berkeley Packet Filter";
    case 0x101: return "WDC 65C816";
    }
    return "Unknown";
}

void printHeader(Elf64_Ehdr elf_header){
	printf("ELF Header:\n");
    printf("Magic:\t");
    for (int i = 0; i < 16; i++)
        printf("%02x ", elf_header.e_ident[i]);
    printf("\nClass:\t");
    if (elf_header.e_ident[4] == 1)
        printf("ELF32\n");
    else
        printf("ELF64\n");
    printf("Data:\t");
    if (elf_header.e_ident[5] == 1)
        printf("little endian\n");
    else
        printf("big endian\n");
    printf("Version: %u\n", elf_header.e_ident[6]);
    printf("OS:\t%s\n", sys_name(elf_header.e_ident[7]));
    printf("ABI Version:\t %u\n", elf_header.e_ident[8]);
    printf("Type:\t%s\n", type_name(elf_header.e_type));
    printf("Machine:\t%s\n", machine_name(elf_header.e_machine));
    printf("Version:\t 0x%x\n", elf_header.e_version);
	printf("Entry point address:\t 0x%lx\n", elf_header.e_entry);
    printf("Start of program headers:\t %lu\n", elf_header.e_phoff);
    printf("Start of section headers:\t %lu\n", elf_header.e_shoff);
	printf("Flags:\t 0x%x\n", elf_header.e_flags);
    printf("Size of this header:\t 64 (bytes)\n");
	printf("Size of program headers:\t %u\n", elf_header.e_phentsize);
    printf("Number of program headers:\t %u\n", elf_header.e_phnum);
    printf("Size of section headers:\t %u\n", elf_header.e_shentsize);
    printf("Number of section headers:\t %u\n", elf_header.e_shnum);
    printf("Section header string table index:\t %u\n", elf_header.e_shstrndx);

}

void print_elf_header64(Elf64_Ehdr elf_header)
{
	printf("ELF header\n");
	/* Storage capacity class */
	printf("Storage class\t= ");
	switch(elf_header.e_ident[EI_CLASS])
	{
		case ELFCLASS32:
			printf("32-bit objects\n");
			break;

		case ELFCLASS64:
			printf("64-bit objects\n");
			break;

		default:
			printf("INVALID CLASS\n");
			break;
	}

	/* Data Format */
	printf("Data format\t= ");
	switch(elf_header.e_ident[EI_DATA])
	{
		case ELFDATA2LSB:
			printf("2's complement, little endian\n");
			break;

		case ELFDATA2MSB:
			printf("2's complement, big endian\n");
			break;

		default:
			printf("INVALID Format\n");
			break;
	}

	/* OS ABI */
	printf("OS ABI\t\t= ");
	switch(elf_header.e_ident[EI_OSABI])
	{
		case ELFOSABI_SYSV:
			printf("UNIX System V ABI\n");
			break;

		case ELFOSABI_HPUX:
			printf("HP-UX\n");
			break;

		case ELFOSABI_NETBSD:
			printf("NetBSD\n");
			break;

		case ELFOSABI_LINUX:
			printf("Linux\n");
			break;

		case ELFOSABI_SOLARIS:
			printf("Sun Solaris\n");
			break;

		case ELFOSABI_AIX:
			printf("IBM AIX\n");
			break;

		case ELFOSABI_IRIX:
			printf("SGI Irix\n");
			break;

		case ELFOSABI_FREEBSD:
			printf("FreeBSD\n");
			break;

		case ELFOSABI_TRU64:
			printf("Compaq TRU64 UNIX\n");
			break;

		case ELFOSABI_MODESTO:
			printf("Novell Modesto\n");
			break;

		case ELFOSABI_OPENBSD:
			printf("OpenBSD\n");
			break;

		case ELFOSABI_ARM_AEABI:
			printf("ARM EABI\n");
			break;

		case ELFOSABI_ARM:
			printf("ARM\n");
			break;

		case ELFOSABI_STANDALONE:
			printf("Standalone (embedded) app\n");
			break;

		default:
			printf("Unknown (0x%x)\n", elf_header.e_ident[EI_OSABI]);
			break;
	}

	/* ELF filetype */
	printf("Filetype \t= ");
	switch(elf_header.e_type)
	{
		case ET_NONE:
			printf("N/A (0x0)\n");
			break;

		case ET_REL:
			printf("Relocatable\n");
			break;

		case ET_EXEC:
			printf("Executable\n");
			break;

		case ET_DYN:
			printf("Shared Object\n");
			break;
		default:
			printf("Unknown (0x%x)\n", elf_header.e_type);
			break;
	}

	/* ELF Machine-id */
	printf("Machine\t\t= ");
	switch(elf_header.e_machine)
	{
		case EM_NONE:
			printf("None (0x0)\n");
			break;

		case EM_386:
			printf("INTEL x86 (0x%x)\n", EM_386);
			break;

		case EM_X86_64:
			printf("AMD x86_64 (0x%x)\n", EM_X86_64);
			break;

		case EM_AARCH64:
			printf("AARCH64 (0x%x)\n", EM_AARCH64);
			break;

		default:
			printf(" 0x%x\n", elf_header.e_machine);
			break;
	}

	/* Entry point */
	printf("Entry point\t= 0x%08lx\n", elf_header.e_entry);

	/* ELF header size in bytes */
	printf("ELF header size\t= 0x%08x\n", elf_header.e_ehsize);

	/* Program Header */
	printf("\nProgram Header\t= ");
	printf("0x%08lx\n", elf_header.e_phoff);		/* start */
	printf("\t\t  %d entries\n", elf_header.e_phnum);	/* num entry */
	printf("\t\t  %d bytes\n", elf_header.e_phentsize);	/* size/entry */

	/* Section header starts at */
	printf("\nSection Header\t= ");
	printf("0x%08lx\n", elf_header.e_shoff);		/* start */
	printf("\t\t  %d entries\n", elf_header.e_shnum);	/* num entry */
	printf("\t\t  %d bytes\n", elf_header.e_shentsize);	/* size/entry */
	printf("\t\t  0x%08x (string table offset)\n", elf_header.e_shstrndx);

	/* File flags (Machine specific)*/
	printf("\nFile flags \t= 0x%08x\n", elf_header.e_flags);

	/* ELF file flags are machine specific.
	 * INTEL implements NO flags.
	 * ARM implements a few.
	 * Add support below to parse ELF file flags on ARM
	 */
	int32_t ef = elf_header.e_flags;
	printf("\t\t  ");

	if(ef & EF_ARM_RELEXEC)
		printf(",RELEXEC ");

	if(ef & EF_ARM_HASENTRY)
		printf(",HASENTRY ");

	if(ef & EF_ARM_INTERWORK)
		printf(",INTERWORK ");

	if(ef & EF_ARM_APCS_26)
		printf(",APCS_26 ");

	if(ef & EF_ARM_APCS_FLOAT)
		printf(",APCS_FLOAT ");

	if(ef & EF_ARM_PIC)
		printf(",PIC ");

	if(ef & EF_ARM_ALIGN8)
		printf(",ALIGN8 ");

	if(ef & EF_ARM_NEW_ABI)
		printf(",NEW_ABI ");

	if(ef & EF_ARM_OLD_ABI)
		printf(",OLD_ABI ");

	if(ef & EF_ARM_SOFT_FLOAT)
		printf(",SOFT_FLOAT ");

	if(ef & EF_ARM_VFP_FLOAT)
		printf(",VFP_FLOAT ");

	if(ef & EF_ARM_MAVERICK_FLOAT)
		printf(",MAVERICK_FLOAT ");

	printf("\n");

	/* MSB of flags conatins ARM EABI version */
	printf("ARM EABI\t= Version %d\n", (ef & EF_ARM_EABIMASK)>>24);

	printf("\n");	/* End of ELF header */

}