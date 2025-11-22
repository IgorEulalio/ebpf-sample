#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main() {
    const char *msg = "Hello from syscalls!\n";

    // stdout write
    write(1, msg, strlen(msg));

    // create a file
    int fd = open("demo.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);

    // write to file
    write(fd, "data123\n", 8);

    // close file
    close(fd);

    // reopen file for reading
    fd = open("demo.txt", O_RDONLY);
    char buf[32];
    read(fd, buf, sizeof(buf));

    // finish
    close(fd);
    return 0;
}
