/* execve.s */
        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx #*envp[]
        push rdx
        mov rax, 0x0068732f6e69622f #"/bin/sh"
        push rax
        mov rdi, rsp    #*pathname
        push rdx
        push rdi
        mov rsi, rsp    #*argv[] 
        xor rax, rax
        mov eax, 0x3b
        syscall

