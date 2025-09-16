#ifndef WOODY_H
#define WOODY_H

#define SUCCES 0
#define ERROR -1
#define KEY_LEN 16

#include <stdio.h>       // FFLUSH FPUTS PERROR
#include <stdlib.h>      // MALOC/FREE
#include <fcntl.h>       // OPEN
#include <sys/syscall.h> // SYSCALL
#include <string.h>      // STRERROR
#include <sys/mman.h>    // MMAP MUNMAP
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>      // CLOSE EXIT LSEEK WRITE
#include <elf.h>         // ELF STRUCTURE
#include <errno.h>
#include <stdbool.h>

typedef struct s_info64 {
	Elf64_Addr parasite_load_address;
	Elf64_Off parasite_offset;
	uint64_t parasite_size;
	int8_t *parasite_code;

    void *cipher_data;
	
	Elf64_Addr orig_entry;
	Elf64_Off code_segment_end_off;
	uint64_t host_filesiz;

    uint64_t text_seg_size;
    Elf64_Off text_seg_off;

    char key[KEY_LEN];
	
	int EXEC;
	int SHARED;
} info64;

int generate_key(info64 *info); 
void patch64(void *file, size_t size, int64_t find, int64_t replace);
void patch32(void *file, size_t size, int32_t find, int32_t replace);
size_t find_32bits(void *file, size_t size, int32_t find);
void patch_size(void *file, size_t size, int64_t find);
void patch_size64_(void *file, size_t size, int64_t find);
void infect(char *path, info64 *info);

#endif
