#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int fd;

void sigio_handler(int signo){
    char buf[256] = {0};
    int ret;
    if(signo != SIGIO){
        fprintf(stderr, "SIGIO handler error!\n");
        exit(-1);
    }
    ret = read(fd, buf, 256);
    if(ret < 0){
        fprintf(stderr, "SIGIO read error!\n");
        exit(-1);
    }
    printf("read %d bytes: %s\n", ret, buf);
}

int main(int argc, char **argv){
    int oflags;
    signal(SIGIO, sigio_handler);
    fd = open("scullpipe", O_RDONLY);
    fcntl(fd, F_SETOWN, getpid());
    oflags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, oflags | O_ASYNC);
    while(1);
    return 0;
}
