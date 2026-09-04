.data 
	wSystemCall DWORD 0000h
	qSyscallInsAddress QWORD 0000h

.code
	
	SetSSn PROC
		mov wSystemCall, 0000h
		mov qSyscallInsAddress, 0000h
		mov wSystemCall, ecx
		mov qSyscallInsAddress, rdx
		ret
	SetSSn ENDP

	RunSyscall PROC
		mov r10, rcx
		mov eax, wSystemCall
		jmp qword ptr[qSyscallInsAddress]; jumping to qSyscallInsAddress instead of calling 'syscall'
		ret
	RunSyscall ENDP

end