	bits 16
	org 100h

	jmp start
	
shuffle_start:
	push 0xB800
	pop es
	mov cx, 80*24*2
	mov ax, 'AA'
	xor di, di
	rep stosw
.lbl:	jmp .lbl
shuffle_end:
	nop
shuffle_len equ (shuffle_end - shuffle_start + 1)

start:
	; calculate physical address of shuffled part
	xor eax, eax
	push ds
	pop ax
	shl eax, 4
	add ax, shuffle_start
	mov dword [source], eax

	mov ax, 0012h
	mov di, shuffle_descriptors
	mov cx, num_shuffle_descriptors
	mov ebp, 0x7c00
	int 22h
	int3

shuffle_descriptors:
	dd 0x7C00
source:	dd 0
	dd shuffle_len

num_shuffle_descriptors equ 1

