#include "woody.h"

int generate_key(info64 *info) {
    int fd;
    if ((fd = open("/dev/random", O_RDONLY)) < 0) { 
        perror("key open");
        return ERROR;
    }

    if ((read(fd, &info->key, KEY_LEN)) != KEY_LEN) {
        perror("keygen");
        close(fd);
        return ERROR;
    }

    close(fd);
}
