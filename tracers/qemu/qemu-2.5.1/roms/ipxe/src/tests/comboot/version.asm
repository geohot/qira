	bits 16
	org 100h

_start:
	; first check for SYSLINUX
	mov ah, 30h
	int 21h

	cmp eax, 59530000h
	jne .not_syslinux
	cmp ebx, 4c530000h
	jne .not_syslinux
	cmp ecx, 4e490000h
	jne .not_syslinux
	cmp edx, 58550000h
	jne .not_syslinux

	; now get syslinux version
	mov ax, 0001h
	int 22h

	push cx
	push dx
	push di
	push si
	push es

	; print version string
	mov dx, str_version
	mov ah, 09h
	int 21h

	pop es
	pop bx
	push es
	mov ax, 0002h
	int 22h

	; print copyright string
	mov dx, str_copyright
	mov ah, 09h
	int 21h

	pop es
	pop bx
	mov ax, 0002h
	int 22h

	; print syslinux derivative id
	mov dx, str_derivative
	mov ah, 09h
	int 21h

	pop ax
	call print_hex_byte

	; print version number
	mov dx, str_version_num
	mov ah, 09h
	int 21h

	pop cx
	push cx
	mov ax, cx
	and ax, 0FFh
	call print_dec_word

	mov dl, '.'
	mov ah, 02h
	int 21h

	pop cx
	mov ax, cx
	shr ax, 8
	call print_dec_word

	ret


.not_syslinux:
	mov dx, str_not_syslinux
	mov ah, 09h
	int 21h
	ret

; input: al = byte to print in hex
print_hex_byte:
	push ax
	shr al, 4
	call print_hex_nybble
	pop ax
	call print_hex_nybble
	ret

; input: bottom half of al = nybble to print in hex
print_hex_nybble:
	push ax
	mov bl, al
	and bx, 1111b
	mov dl, [str_hex + bx]
	mov ah, 02h
	int 21h
	pop ax
	ret

str_hex: db "01234567890abcdef"

; input: ax = word to print
print_dec_word:
	mov cx, 10
	mov word [.count], 0
.loop:
	xor dx, dx
	div cx
	inc word [.count]
	push dx
	test ax, ax
	jnz .loop

.print:
	pop dx
	add dx, '0'
	mov ah, 02h
	int 21h
	dec word [.count]
	jnz .print

	ret

.count:	dw 0

str_not_syslinux: db "Not SYSLINUX or derivative (running on DOS?)$"
str_version: db "Version: $"
str_copyright: db 10, "Copyright: $"
str_derivative: db 10, "Derivative ID: 0x$"
str_version_num: db 10, "Version number: $"
