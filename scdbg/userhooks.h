
#define POP_DWORD(cpu, dst_p) \
{ int32_t ret = emu_memory_read_dword(cpu->mem, cpu->reg[esp], dst_p); \
if( ret != 0 ) \
	return ret; \
else \
	cpu->reg[esp] += 4; }

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

uint32_t user_hook_ExitProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_ExitThread(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateProcess(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_exit(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_accept(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_bind(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_closesocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_connect(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fclose(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fopen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_fwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_listen(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_recv(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_send(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_socket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WSASocket(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CreateFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WriteFile(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_CloseHandle(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...);

//added 1-20-11 - dzzie (req'd dll mod)
uint32_t user_hook_GetProcAddress(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetSystemDirectoryA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetTickCount(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_LoadLibraryA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lcreat(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lwrite(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook__lclose(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_malloc(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_memset(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_SetUnhandledExceptionFilter(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_WinExec(struct emu_env *env, struct emu_env_hook *hook, ...); //did not req dll mod

//added 1-21-11 dzzie when moved to latest dll
uint32_t user_hook_DeleteFileA(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetVersion(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_GetTempPath(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_Sleep(struct emu_env *env, struct emu_env_hook *hook, ...);
uint32_t user_hook_VirtualProtect(struct emu_env *env, struct emu_env_hook *hook, ...);

//1-26-11 - another dll mod to allow for user hooking of arbitrary functions
int32_t	new_user_hook_GetModuleHandleA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_GenericStub(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_MessageBoxA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_ShellExecuteA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_SHGetSpecialFolderPathA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_CreateProcessInternalA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_GlobalAlloc(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_MapViewOfFile(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_URLDownloadToCacheFileA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_system(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_VirtualAlloc(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_GenericStub2String(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_VirtualProtectEx(struct emu_env *env, struct emu_env_hook *hook);

//added 3-7-11 w/fopen option..
int32_t	new_user_hook_SetFilePointer(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_ReadFile(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_strstr(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_strtoul(struct emu_env *env, struct emu_env_hook *hook);

int32_t	new_user_hook_GetTempFileNameA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_LoadLibrary(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_GetModuleFileNameA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_DialogBoxIndirectParamA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_ZwQueryVirtualMemory(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_GetEnvironmentVariableA(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_VirtualAllocEx(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_WriteProcessMemory(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_CreateRemoteThread(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_MultiByteToWideChar(struct emu_env *env, struct emu_env_hook *hook);
int32_t	new_user_hook_CreateFileW(struct emu_env *env, struct emu_env_hook *hook);
