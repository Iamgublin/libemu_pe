
#include "emu_memory.h"
#pragma warning(disable: 4311)
#pragma warning(disable: 4312)
#pragma warning(disable: 4267)

#define PUSH_DWORD(cpu, arg)							\
{														\
	uint32_t pushme;									\
	bcopy(&(arg),  &pushme, 4);							\
	if (cpu->reg[esp] < 4)								\
	{													\
		emu_errno_set((cpu)->emu, ENOMEM);				\
		emu_strerror_set((cpu)->emu,					\
		"ran out of stack space writing a dword\n");	\
		return -1;										\
	}													\
	cpu->reg[esp]-=4;									\
	{																			\
		int32_t memret = emu_memory_write_dword(cpu->mem, cpu->reg[esp], pushme);	\
		if (memret != 0)														\
			return memret;														\
	}																			\
}

//1-26-11 - another dll mod to allow for user hooking of arbitrary functions
int32_t	__stdcall hook_GetModuleHandleA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GenericStub(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_MessageBoxA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_ShellExecuteA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_SHGetSpecialFolderPathA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CreateProcessInternalA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GlobalAlloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_MapViewOfFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_URLDownloadToCacheFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_system(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_VirtualAlloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GenericStub2String(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_VirtualProtectEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);

//added 3-7-11 w/fopen option..
int32_t	__stdcall hook_SetFilePointer(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_ReadFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_strstr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_strtoul(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);

int32_t	__stdcall hook_GetTempFileNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_LoadLibraryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetModuleFileNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_DialogBoxIndirectParamA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_ZwQueryVirtualMemory(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetEnvironmentVariableA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_VirtualAllocEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WriteProcessMemory(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CreateRemoteThread(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_MultiByteToWideChar(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CreateFileW(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);

//from conversion
int32_t	__stdcall hook_URLDownloadToFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_execv(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_fclose(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_fopen(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_fwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook__lcreat(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook__lclose(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook__lwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetTempPathA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetTickCount(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook__hwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WinExec(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_Sleep(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_DeleteFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_ExitProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CloseHandle(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CreateFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CreateProcessA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetVersion(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetProcAddress(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetSystemDirectoryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_malloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_memset(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_SetUnhandledExceptionFilter(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WaitForSingleObject(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WriteFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_VirtualProtect(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_bind(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_accept(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_bind(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_closesocket(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_connect(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_listen(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_recv(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_send(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_sendto(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_socket(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WSASocketA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WSAStartup(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);

//new
int32_t	__stdcall hook_CreateFileMappingA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_WideCharToMultiByte(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetLogicalDriveStringsA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_FindWindowA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_DeleteUrlCacheEntryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_FindFirstFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_shdocvw65(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetUrlCacheEntryInfoA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_CopyFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetFileSize(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_EnumWindows(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetClassNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_fread(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_IsBadReadPtr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
int32_t	__stdcall hook_GetCommandLineA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);












