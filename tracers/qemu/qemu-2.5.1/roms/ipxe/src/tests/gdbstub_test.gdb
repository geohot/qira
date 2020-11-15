#!/usr/bin/gdb -x
# Test suite for GDB remote debugging
# Run:
#   make bin/ipxe.hd.tmp
#   make
#   gdb
#   (gdb) target remote :TCPPORT
#   OR
#   (gdb) target remote udp:IP:UDPPORT
#   (gdb) source tests/gdbstub_test.gdb

define ipxe_load_symbols
	file bin/ipxe.hd.tmp
end

define ipxe_assert
	if $arg0 != $arg1
		echo FAIL $arg2\n
	else
		echo PASS $arg2\n
	end
end

define ipxe_start_tests
	jump gdbstub_test
end

define ipxe_test_regs_read
	ipxe_assert $eax 0xea010203 "ipxe_test_regs_read eax"
	ipxe_assert $ebx 0xeb040506 "ipxe_test_regs_read ebx"
	ipxe_assert $ecx 0xec070809 "ipxe_test_regs_read ecx"
	ipxe_assert $edx 0xed0a0b0c "ipxe_test_regs_read edx"
	ipxe_assert $esi 0x510d0e0f "ipxe_test_regs_read esi"
	ipxe_assert $edi 0xd1102030 "ipxe_test_regs_read edi"
end

define ipxe_test_regs_write
	set $eax = 0xea112233
	set $ebx = 0xeb445566
	set $ecx = 0xec778899
	set $edx = 0xedaabbcc
	set $esi = 0x51ddeeff
	set $edi = 0xd1010203
	c
	ipxe_assert $eax 0xea112233 "ipxe_test_regs_write eax"
	ipxe_assert $ebx 0xeb445566 "ipxe_test_regs_write ebx"
	ipxe_assert $ecx 0xec778899 "ipxe_test_regs_write ecx"
	ipxe_assert $edx 0xedaabbcc "ipxe_test_regs_write edx"
	ipxe_assert $esi 0x51ddeeff "ipxe_test_regs_write esi"
	ipxe_assert $edi 0xd1010203 "ipxe_test_regs_write edi"

	# This assumes segment selectors are always 0x10 or 0x8 (for code).
	ipxe_assert $cs 0x08 "ipxe_test_regs_write cs"
	ipxe_assert $ds 0x10 "ipxe_test_regs_write ds"
end

define ipxe_test_mem_read
	c
	ipxe_assert ({int}($esp+4)) 0x11223344 "ipxe_test_mem_read int"
	ipxe_assert ({short}($esp+2)) 0x5566 "ipxe_test_mem_read short"
	ipxe_assert ({char}($esp)) 0x77 "ipxe_test_mem_read char"
end

define ipxe_test_mem_write
	set ({int}($esp+4)) = 0xaabbccdd
	set ({short}($esp+2)) = 0xeeff
	set ({char}($esp)) = 0x99
	c
	ipxe_assert ({int}($esp+4)) 0xaabbccdd "ipxe_test_mem_write int"
	ipxe_assert ({short}($esp+2)) (short)0xeeff "ipxe_test_mem_write short"
	ipxe_assert ({char}($esp)) (char)0x99 "ipxe_test_mem_write char"
end

define ipxe_test_step
	c
	si
	ipxe_assert ({char}($eip-1)) (char)0x90 "ipxe_test_step" # nop = 0x90
end

define ipxe_test_awatch
	awatch watch_me

	c
	ipxe_assert $ecx 0x600d0000 "ipxe_test_awatch read"
	if $ecx == 0x600d0000
		c
	end

	c
	ipxe_assert $ecx 0x600d0001 "ipxe_test_awatch write"
	if $ecx == 0x600d0001
		c
	end

	delete
end

define ipxe_test_watch
	watch watch_me
	c
	ipxe_assert $ecx 0x600d0002 "ipxe_test_watch"
	if $ecx == 0x600d0002
		c
	end
	delete
end

ipxe_load_symbols
ipxe_start_tests
ipxe_test_regs_read
ipxe_test_regs_write
ipxe_test_mem_read
ipxe_test_mem_write
ipxe_test_step
ipxe_test_awatch
ipxe_test_watch
