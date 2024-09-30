#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <libgen.h>

#include "rivit_common.h"

// #define DEBUG(code) (code);
#define DEBUG(code) 

char* lock_file = "/tmp/.eraser";

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void shift_array(u8* data, u64 size, u64 off) {
    memmove(&data[off], &data[off+1], size);
}

int rewrite_file(char* path, u64 offset) {
    struct stat st;
    CHECKED_CALL(stat(path, &st));
    u64 file_size = st.st_size;

    if((st.st_mode & S_IFMT) != S_IFREG) {
        DEBUG(fprintf(stderr, "not a regular file\n"));
        return 2;
    }

    int fd;
    CHECKED_CALL(fd = open(path, O_RDONLY));

    int copy_fd;
    char temp_path[0x1000] = {};
    snprintf(temp_path, sizeof(temp_path), "/tmp/.%s.tmp", basename(path));

    CHECKED_CALL(copy_fd = open(temp_path, O_CREAT | O_WRONLY, st.st_mode));

    DEBUG(printf("Target: %s, offset: %lu, file size: %lu\n", path, offset, file_size));

    if(offset >= file_size) {
        DEBUG(fprintf(stderr, "offset too large\n"));
        return 3;
    }

    u8 buffer[0x1000];
    u64 read_so_far = 0;
    u64 left;
    int n;
    while((left = (file_size - read_so_far)) > 0) {
        u64 chunk_len = MIN(left, sizeof(buffer));

        memset(buffer, 0, sizeof(buffer));
        CHECKED_CALL(n = read(fd, buffer, chunk_len));
        if(chunk_len != n){
            DEBUG(fprintf(stderr, "read less bytes than expected\n"));
            return 4;
        }

        if(read_so_far <= offset && offset < read_so_far + n){
            u64 rel_offset = offset - read_so_far;
            chunk_len -= 1;
            shift_array(buffer, chunk_len - rel_offset, rel_offset);
        }

        read_so_far += n;

        CHECKED_CALL(n = write(copy_fd, buffer, chunk_len));
        if(chunk_len != n){
            DEBUG(fprintf(stderr, "written less bytes than expected\n"));
            return 5;
        }
    }

    CHECKED_CALL(close(fd));
    CHECKED_CALL(close(copy_fd));
    CHECKED_CALL(rename(temp_path, path));
    CHECKED_CALL(chown(path, st.st_uid, st.st_gid));
    CHECKED_CALL(chmod(path, st.st_mode));
    CHECKED_CALL(fd = open(lock_file, O_CREAT, S_IRUSR | S_IRGRP));
    CHECKED_CALL(close(fd));
    return 0;
}

int file_exists(char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int main(int argc, char* argv[]) {
    if(argc != 3) {
        DEBUG(fprintf(stderr, "Usage: eraser <file> <offset>\nDeletes one byte from the specified offset for a given file\n"));
        return -1;
    }

    setup();

    if(file_exists(lock_file)) {
        DEBUG(fprintf(stderr, "You already used your opportunity\n"));
        return 1;
    }

    u64 offset = strtoull(argv[2], NULL, 10);
    return rewrite_file(argv[1], offset);
}
