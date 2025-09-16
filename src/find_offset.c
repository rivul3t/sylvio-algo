#include "woody.h"

void patch64(void *file, size_t size, int64_t find, int64_t replace) {
    for (uint64_t i = 0; i < size; i++) {
        int64_t qword = *(int64_t *)(file + i);
        if (!(qword ^ find))
            *(int64_t *)(file + i) = replace;
    }
}

void patch32(void *file, size_t size, int32_t find, int32_t replace) {
    for (uint64_t i = 0; i < size; i++) {
        int32_t qword = *(int32_t *)(file + i);
        if (!(qword ^ find))
            *(int32_t *)(file + i) = replace;
    }
}

size_t find_32bits(void *file, size_t size, int32_t find) {
    for (uint64_t i = 0; i < size; i++) {
        int32_t qword = *(int32_t *)(file + i);
        if (!(qword ^ find))
            return i;
    }
}

void patch_size(void *file, size_t size, int64_t find) {
    for (uint64_t i = 0; i < size; i++) {
        int64_t qword = *(int64_t *)(file + i);
        if (!(qword ^ find))
            *(uint64_t *)(file + i) = (uint64_t) i;
    }
}

void patch_size64_(void *file, size_t size, int64_t find) {
    for (uint32_t i = 0; i < size; i++) {
        int32_t qword = *(int32_t *)(file + i);
        if (!(qword ^ find)) {
            *(uint32_t *)(file + i) = (uint32_t) (i - 2);
        }
    }
}
