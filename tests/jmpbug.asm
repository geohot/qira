mov eax, 3

fail:
mov ebx, 2
sub eax, 1
cmp eax, 0
jne fail

mov eax, 1
int 0x80

