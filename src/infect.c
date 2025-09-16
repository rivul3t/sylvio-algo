#include "woody.h"

extern void _rc4_cipher(void *bytes, uint64_t length, const char *key, uint32_t keysize);
extern char *rc4_cipher_start(void *data, int datalen, char *key, int keylen);

void *mmapFile(char *path, info64 *info);
int getPaddingSize(void *file, info64 *info);
void patchSht(void *file, info64 *info);
int findRet2eopOff(info64 *info);
void _xor(void *file, uint64_t filesz, char *key, uint64_t key_len);

void infect(char *path, info64 *info) {
	void *file = mmapFile(path, info);
	Elf64_Off padd_size, ret2oep;
	Elf64_Ehdr *host_hdr = (Elf64_Ehdr *) file;
	
	if (host_hdr->e_type == ET_EXEC) {
		info->EXEC = 1;
		info->SHARED = 0;
	}
	else if (host_hdr->e_type == ET_DYN) {
		info->EXEC = 0;
		info->SHARED = 1;
	} else return;

	padd_size = getPaddingSize(file, info);
	if (padd_size < info->parasite_size + KEY_LEN) return;

	info->orig_entry = host_hdr->e_entry;
	if (info->EXEC) host_hdr->e_entry = info->parasite_load_address;
	else if (info->SHARED) host_hdr->e_entry = info->parasite_offset;

	patchSht(file, info);
	ret2oep = findRet2eopOff(info);

    patch_size64_(info->parasite_code, info->parasite_size, 0x31313131/*0x81818181*/);
    patch32(info->parasite_code, info->parasite_size, 0x99999999, info->parasite_offset);

    patch_size64_(info->parasite_code, info->parasite_size, 0x71717171);
    patch32(info->parasite_code, info->parasite_size, 0x72727272, info->parasite_offset);
    patch32(info->parasite_code, info->parasite_size, 0x73737373, info->orig_entry);

    patch32(info->parasite_code, info->parasite_size, 0x22222222, info->parasite_offset - info->orig_entry/*info->text_seg_size*/);
    patch32(info->parasite_code, info->parasite_size, 0x33333333, info->text_seg_off);
    patch32(info->parasite_code, info->parasite_size, 0x44444444, KEY_LEN);
    patch32(info->parasite_code, info->parasite_size, 0x55555555, info->parasite_offset + info->parasite_size);

    patch32(info->parasite_code, info->parasite_size, 0x14141414, info->parasite_offset - info->orig_entry/*info->text_seg_size*/);

    generate_key(info);
    info->cipher_data = malloc(info->text_seg_size + 8);

    _xor(/*file + info->text_seg_off*/ file + info->orig_entry, info->parasite_offset - info->orig_entry/*info->text_seg_size*/, info->key, KEY_LEN);

    size_t key_offset = find_32bits(info->parasite_code, info->parasite_size, 0x48484848);

    memcpy(info->parasite_code + key_offset, info->key, KEY_LEN);


    void *inject_addr = file + info->parasite_offset;
	memcpy(inject_addr, info->parasite_code, info->parasite_size);
    inject_addr += info->parasite_size;
    memcpy(inject_addr, info->key, KEY_LEN);


	munmap(file, info->host_filesiz);
}

void *mmapFile(char *path, info64 *info) {
	int fd = open(path, O_RDWR);
	if (!fd) perror("Open");
	
	struct stat st;
	if (fstat(fd, &st)) perror("fstat");
	info->host_filesiz = st.st_size;
	
	void *file = mmap(NULL,	info->host_filesiz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	return file; 
}

int getPaddingSize(void *file, info64 *info) {
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *curr_phdr = (Elf64_Phdr *)(file + hdr->e_phoff);
	uint16_t pcount = hdr->e_phnum;
	int find = 0;

	for (int i = 0; i < pcount; i++) {
		if ((!find) && (curr_phdr->p_type == PT_LOAD) && (curr_phdr->p_flags == (PF_R | PF_X))) {
			find = 1;

			info->code_segment_end_off = curr_phdr->p_offset + curr_phdr->p_filesz;
			info->parasite_offset = curr_phdr->p_offset + curr_phdr->p_filesz;
			info->parasite_load_address = curr_phdr->p_vaddr + curr_phdr->p_filesz;

            info->text_seg_size = curr_phdr->p_filesz;
            info->text_seg_off = curr_phdr->p_offset;

			curr_phdr->p_filesz += info->parasite_size;
			curr_phdr->p_memsz += info->parasite_size;
		}

		if (find && (curr_phdr->p_type == PT_LOAD) && (curr_phdr->p_flags == (PF_R | PF_W))) 
			return (curr_phdr->p_offset - info->code_segment_end_off);
		curr_phdr++;
	}
	return 0;
}

void patchSht(void *file, info64 *info) {
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Shdr *shdr = (Elf64_Shdr *) (file + hdr->e_shoff);
	
	for (int i = 0; i < hdr->e_shnum; i++) {
		if (shdr->sh_offset == info->code_segment_end_off)
			shdr->sh_size += info->parasite_size;
		shdr++;
	}
}

int findRet2eopOff(info64 *info) {
	for (size_t i = 0; i < info->parasite_size; i++)
    {
        if (((char *)info->parasite_code)[i] == 0x77)
        {
            if (info->parasite_size - i > 17)
            {
                // Actually checking we are in ret2oep
                if (((char *)info->parasite_code)[i + 1] == 0x77 && ((char *)info->parasite_code)[i + 2] == 0x77 &&
                    ((char *)info->parasite_code)[i + 3] == 0x77 &&
                    ((char *)info->parasite_code)[i + 4] == 0x48 && ((char *)info->parasite_code)[i + 5] == 0x2d &&
                    ((char *)info->parasite_code)[i + 6] == 0x77 && ((char *)info->parasite_code)[i + 7] == 0x77 &&
                    ((char *)info->parasite_code)[i + 8] == 0x77 && ((char *)info->parasite_code)[i + 9] == 0x77 &&
                    ((char *)info->parasite_code)[i + 10] == 0x48 && ((char *)info->parasite_code)[i + 11] == 0x05 &&
                    ((char *)info->parasite_code)[i + 12] == 0x77 && ((char *)info->parasite_code)[i + 13] == 0x77 &&
                    ((char *)info->parasite_code)[i + 14] == 0x77 && ((char *)info->parasite_code)[i + 15] == 0x77)
                {
                    // Removing 2 to go to actual start of ret2oep (go back to instructions sub).
                    return i - 2;
                }
            }
        }
    }	
}

void _xor(void *file, uint64_t filesz, char *key, uint64_t key_len) {
    for (uint64_t i = 0; i < filesz; i++) {
        int8_t *byt = (int8_t *) (file + i);
        (*byt) ^= key[i % key_len];
    }
}

int64_t str_to_int64(char *source) {
    int64_t res = 0;
    for (int i = 0; i < 8; i++) {
        
    }
}
