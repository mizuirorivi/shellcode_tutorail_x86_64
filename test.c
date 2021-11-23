/* execve.c */
#include <unistd.h>

int main()
{
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}