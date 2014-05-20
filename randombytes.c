#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

static int fd = -1;

void randombytes(unsigned char *ptr,unsigned long long length) {
    unsigned int n = 0;
    unsigned int i = 0;
    if (fd == -1) {
        if ((fd = open("/dev/urandom",O_RDONLY)) == -1) {
            err(1,"Error opening /dev/urandom");
        }
    }
    while (length > 0) {
        i = (length > 65536) ? 65536 : length;
        i = read(fd,ptr,i);
        ptr += i;
        length -= i;
    }
}
