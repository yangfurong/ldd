#include <sys/select.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define LOG(fmt, args...) fprintf(stderr, fmt, ##args)

int main(int argc, char **argv){
    int fd = open("scullpipe", O_RDWR);
    fd_set r_fds, w_fds;
    int ret = -1;
    char buf[1024];
    char *halo = "halo";
    while(1){
        FD_ZERO(&w_fds);
        FD_ZERO(&r_fds);
        FD_SET(fd, &r_fds);
        //FD_SET(fd, &w_fds);
        ret = select(fd + 1, &r_fds, &w_fds, NULL, NULL);
        if(ret == -1){
            LOG("select return -1!\n");
            return ret;
        }
        if(FD_ISSET(fd, &r_fds)){
            memset(buf, 0, 1024);
            ret = read(fd, buf, 1024);
            if(ret < 0){
                LOG("read failed! %d\n", ret);
                return ret;
            }
            printf("read %d bytes: %s\n", ret, buf);
        }
        if(FD_ISSET(fd, &w_fds)){
            ret = write(fd, halo, 4);
            if(ret < 0){
                LOG("write failed! %d\n", ret);
                return ret;
            }
            printf("write %d bytes: %s\n", ret, halo);
        }
    }
    return 0;
}
