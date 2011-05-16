/********************************************************************************
 *                               libemu
 *
 *                    - x86 shellcode emulation -
 *
 *
 * Copyright (C) 2007  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/




#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include "emu.h"
#include "emu_memory.h"
#include "emu_cpu.h"
#include "emu_log.h"
#include "emu_cpu_data.h"
#include "emu_cpu_stack.h"
#include "emu_env.h"
#include "emu_env_w32.h"
#include "emu_env_w32_dll.h"
#include "emu_env_w32_dll_export.h"
#include "emu_string.h"

extern "C"{
	#include "emu_hashtable.h"
}

#include "userhooks.h"
#include "options.h"
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <winsock.h>
#include <windows.h>

extern int CODE_OFFSET;
extern uint32_t FS_SEGMENT_DEFAULT_OFFSET;
extern void hexdump(unsigned char*, int);
extern int file_length(FILE *f);
extern void add_malloc(uint32_t, uint32_t);
extern char* dllFromAddress(uint32_t addr);
extern bool FolderExists(char* folder);
extern struct emu_memory *mem;
extern struct emu_cpu *cpu;    //these two are global in main code
//extern struct nanny* na;       //this was passed around as user data in case of multithreading..but were not.
extern bool disable_mm_logging;
int last_GetSizeFHand = -44;
int rep_count=0;
bool gfs_scan_warn = false;

int nextFhandle = 0;

uint32_t MAX_ALLOC  = 0x1000000;
uint32_t next_alloc = 0x60000; //these increment so we dont walk on old allocs


int get_fhandle(void){
	nextFhandle+=4;
	return nextFhandle;
}

/*these next 2 (maybe 3) seem to be the cleanest way to load args from the stack...*/
uint32_t popd(void){
	uint32_t x=0;
	emu_memory_read_dword(cpu->mem, cpu->reg[esp], &x); 
	cpu->reg[esp] += 4; 
	return x;
}

struct emu_string* popstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_string(mem, addr, str, 1256);
	return str;
}


void loadargs(int count, uint32_t ary[]){
	for(int i=0;i<count;i++){
		int32_t ret = emu_memory_read_dword(cpu->mem, cpu->reg[esp], &ary[i]); 
		if( ret != 0 ){
			printf("Error reading stack %x\n", cpu->reg[esp]);
			exit(0);
		}
		cpu->reg[esp] += 4; 
	}
}

char* SafeTempFile(void){
	char* buf = (char*)malloc(300);
	GetTempPath(255, buf);
	return strncat(buf,tmpnam(NULL),299);
}


void set_ret(uint32_t val){ cpu->reg[eax] = val; } 

//by the time our user call is called, the args have already been popped off the stack.
//in r/t that just means that esp has been adjusted and cleaned up for function to 
//return, since there hasnt been any memory writes, we can still grab the return address
//off the stack if we know the arg sizes and calculate it with teh adjustment.
//little bit more work, but safe and doesnt require any otherwise sweeping changes
//to the dll - dzzie

uint32_t get_ret(struct emu_env *env, int arg_adjust){

	struct emu_memory *m = emu_memory_get(env->emu);
	uint32_t reg_esp = cpu->reg[esp];
	uint32_t ret_val = 0;
	
	emu_memory_read_dword( m, reg_esp+arg_adjust, &ret_val);
	
	if(opts.adjust_offsets){
		if( (ret_val > CODE_OFFSET) &&  (ret_val <= (CODE_OFFSET + opts.size)) ){
			return ret_val - CODE_OFFSET; //adjusted to file offset of input file
		}else{
			return ret_val; //return the raw value from stack
		}
	}else{
		return ret_val; //return the raw value from stack
	}

}

char* get_client_ip(struct sockaddr *clientInformation)
{	
	if (clientInformation->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)clientInformation;
		return inet_ntoa(ipv4->sin_addr);
	}
	return 0;
}

unsigned int get_client_port(struct sockaddr *clientInformation)
{
	unsigned int portNumber;
	if (clientInformation->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)clientInformation;
		portNumber = ntohs(ipv4->sin_port);
		return portNumber;
	}
	return 0;
}

void set_next_alloc(int size){  //space allocs at 0x1000 bytes for easy offset recgonition..
	add_malloc(next_alloc, size); //record current one for dumping if need be..
	if(size % 1000 == 0){
		size += 0x1000;
	}else{
		while( size % 0x1000 != 0) size++;
	}
	next_alloc += size;
	//printf("next_alloc=%x\n", next_alloc);
}

void GetSHFolderName(int id, char* buf255){
	
	switch(id){
		case 0:      strcpy(buf255, "./DESKTOP"); break;
		case 1:      strcpy(buf255, "./INTERNET");break;
		case 2:      strcpy(buf255, "./PROGRAMS");break;
		case 3:      strcpy(buf255, "./CONTROLS");break;
		case 4:      strcpy(buf255, "./PRINTERS");break;
		case 5:      strcpy(buf255, "./PERSONAL");break;
		case 6:      strcpy(buf255, "./FAVORITES");break;
		case 7:      strcpy(buf255, "./STARTUP");break;
		case 8:      strcpy(buf255, "./RECENT");break;
		case 9:      strcpy(buf255, "./SENDTO");break;
		case 0xA:    strcpy(buf255, "./BITBUCKET");break;
		case 0xB:    strcpy(buf255, "./STARTMENU");break;
		case 0x0010: strcpy(buf255, "./DESKTOPDIRECTORY");break;
		case 0x0011: strcpy(buf255, "./DRIVES"); break;
		case 0x0012: strcpy(buf255, "./NETWORK"); break;
		case 0x0013: strcpy(buf255, "./NETHOOD");break;
		case 0x0014: strcpy(buf255, "./FONTS");break;
		case 0x0015: strcpy(buf255, "./TEMPLATES");break;
		case 0x0016: strcpy(buf255, "./COMMON_STARTMENU");break;
		case 0x0017: strcpy(buf255, "./COMMON_PROGRAMS");break;
		case 0x0018: strcpy(buf255, "./COMMON_STARTUP");break;
		case 0x0019: strcpy(buf255, "./COMMON_DESKTOPDIRECTORY");break;
		case 0x001a: strcpy(buf255, "./APPDATA");break;
		case 0x001b: strcpy(buf255, "./PRINTHOOD");break;
		case 0x001d: strcpy(buf255, "./ALTSTARTUP");break;
		case 0x001e: strcpy(buf255, "./COMMON_ALTSTARTUP");break;
		case 0x001f: strcpy(buf255, "./COMMON_FAVORITES");break;
		case 0x0020: strcpy(buf255, "./INTERNET_CACHE");break;
		case 0x0021: strcpy(buf255, "./COOKIES");break;
		case 0x0022: strcpy(buf255, "./HISTORY");break;
		default: sprintf(buf255,"Unknown CSIDL: %x",id);
	}

}

int32_t	__stdcall new_user_hook_GetModuleHandleA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{   //HMODULE WINAPI GetModuleHandle( __in_opt  LPCTSTR lpModuleName);
	uint32_t eip_save = popd();
	struct emu_string *s_filename = popstring();
	char *dllname = emu_string_char(s_filename);

	int i=0;
	int found_dll = 0;
	cpu->reg[eax] = 0; //default = fail

	for (i=0; env->env.win->loaded_dlls[i] != NULL; i++)
	{
		if (stricmp(env->env.win->loaded_dlls[i]->dllname, dllname) == 0)
		{
			cpu->reg[eax]= env->env.win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
			break;
		}
	}
	 
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(env->env.win, dllname) == 0)
        {
            cpu->reg[eax] = env->env.win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
        }
	}

	printf("%x\tGetModuleHandleA(%s)\n",eip_save,  dllname);

	emu_string_free(s_filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_MessageBoxA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{	/*int WINAPI MessageBox(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption, UINT uType);*/
	uint32_t eip_save = popd();
	uint32_t hwnd = popd();
	struct emu_string *s_text = popstring();
	struct emu_string *s_cap = popstring();
	uint32_t utype = popd();
	
	printf("%x\tMessageBoxA(%s, %s)\n", eip_save, emu_string_char(s_text), emu_string_char(s_cap) );
	
	emu_string_free(s_text);
	emu_string_free(s_cap);

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_ShellExecuteA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
HINSTANCE ShellExecute(
  __in_opt  HWND hwnd,
  __in_opt  LPCTSTR lpOperation,
  __in      LPCTSTR lpFile,
  __in_opt  LPCTSTR lpParameters,
  __in_opt  LPCTSTR lpDirectory,
  __in      INT   nShowCmd
);

*/
	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t lpOperation;
	POP_DWORD(c, &lpOperation);

	uint32_t p_file;
	POP_DWORD(c, &p_file);

	uint32_t lpParameters;
	POP_DWORD(c, &lpParameters);

	uint32_t lpDirectory;
	POP_DWORD(c, &lpDirectory);

	uint32_t nShowCmd;
	POP_DWORD(c, &nShowCmd);

	struct emu_string *s_text = emu_string_new();
	emu_memory_read_string(mem, p_file, s_text, 254);

	struct emu_string *s_param = emu_string_new();
	emu_memory_read_string(mem, lpParameters, s_param, 254);

	char *stext = emu_string_char(s_text);
	printf("%x\tShellExecuteA(%s, %s)\n",eip_save,  stext, emu_string_char(s_param) );
	
	emu_string_free(s_text);
	emu_string_free(s_param);

	cpu->reg[eax] = 33;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_SHGetSpecialFolderPathA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
CopyBOOL SHGetSpecialFolderPath(
         HWND hwndOwner,
  __out  LPTSTR lpszPath,
  __in   int csidl,
  __in   BOOL fCreate
);

*/
	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t csidl;
	POP_DWORD(c, &csidl);

	uint32_t fCreate;
	POP_DWORD(c, &fCreate);

	char buf255[255];
	memset(buf255,0,254);
	GetSHFolderName(csidl, (char*)&buf255);

	printf("%x\tSHGetSpecialFolderPathA(buf=%x, %s)\n",eip_save, buf, buf255 );
	
	emu_memory_write_block(mem,buf,buf255,strlen(buf255));

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GenericStub(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	BOOL InternetReadFile(
	  __in   HINTERNET hFile,
	  __out  LPVOID lpBuffer,
	  __in   DWORD dwNumberOfBytesToRead,
	  __out  LPDWORD lpdwNumberOfBytesRead
	);

    ZwTerminateProcess, ZwTerminateThread, each 2 args
    BOOL WINAPI TerminateThread(inout HANDLE hThread, DWORD dwExitCode)
	FreeLibrary(hMod)
	handle GetCurrentProcess(void)

    HANDLE WINAPI CreateThread(
	  __in_opt   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	  __in       SIZE_T dwStackSize,
	  __in       LPTHREAD_START_ROUTINE lpStartAddress,
	  __in_opt   LPVOID lpParameter,
	  __in       DWORD dwCreationFlags,
	  __out_opt  LPDWORD lpThreadId
	);

    void WINAPI GetSystemTime(
	  __out  LPSYSTEMTIME lpSystemTime
	);

	BOOL WINAPI FlushViewOfFile(
	  __in  LPCVOID lpBaseAddress,
	  __in  SIZE_T dwNumberOfBytesToFlush
	);

  BOOL WINAPI UnmapViewOfFile(  __in  LPCVOID lpBaseAddress );
  BOOL WINAPI FindClose(  __inout  HANDLE hFindFile );




);


*/
	int dwCreationFlags=0;

	int arg_count = -1 ;
	int ret_val   =  1 ;
    int log_val   = -1 ; //stub support optional logging of two int arg
	int log_val2  = -1 ; 

	char* func = ex->fnname;

	if(strcmp(func, "GetCurrentProcess") ==0 ){
		arg_count = 0;
	}

	if(strcmp(func, "RtlDestroyEnvironment") ==0 ){
		arg_count = 1;
	}

	if(strcmp(func, "FindClose") == 0 ){
		arg_count = 1;
	}

	if(strcmp(func, "FlushViewOfFile") ==0 ){
		arg_count = 2;
		log_val = get_ret(env,0);  //base address
		log_val2 = get_ret(env,4);  //size
	}

	if(strcmp(func, "UnmapViewOfFile") ==0 ){
		arg_count = 1;
		log_val = get_ret(env,0);  //base address
	}
	

	if(strcmp(func, "GetSystemTime") ==0 ){
		arg_count = 0;
		log_val = get_ret(env,0);  //lpSystime
		//struct SYSTEMTIME st;
		//memset(&st,7, 16);
		//st.wYear = 2011;
		//emu_memory_write_block( mem, log_val, &st, 16);
	}

	if(strcmp(func, "FreeLibrary") ==0 ){
		log_val = get_ret(env,0);  //hmodule
		arg_count = 1;
	}

	if(strcmp(func, "CreateThread") ==0 ){
		log_val = get_ret(env,8);  //start address
		log_val2 = get_ret(env,12);  //parameter
		dwCreationFlags = get_ret(env,16);
		//todo handle optional threadID parameter in case of resume thread...(make this its own stub)
		arg_count = 6;
	}

	if(strcmp(func, "GlobalFree") ==0 ){
		log_val = get_ret(env,0);  //hmem
		ret_val = 0;
		arg_count = 1;
	}

	if(strcmp(func, "RevertToSelf") ==0 ){
		arg_count = 0;
	}

	if(strcmp(func, "GetFileSize") == 0){
		log_val = get_ret(env,0); //handle
		if( log_val < 5 && opts.h_fopen > 0 )
			ret_val = opts.fopen_fsize + opts.adjust_getfsize;
		else
			ret_val = GetFileSize( (HANDLE)log_val, 0)+opts.adjust_getfsize;
		arg_count = 2;
	}

	if(strcmp(func, "RtlExitUserThread") ==0 ){
		arg_count = 1;
		log_val = get_ret(env,0); //handle
		opts.steps =0;
	}

	if(strcmp(func, "ZwTerminateProcess") == 0 
		|| strcmp(func, "ZwTerminateThread") == 0
		|| strcmp(func, "TerminateThread") == 0
		|| strcmp(func, "TerminateProcess") == 0
	){
		log_val = get_ret(env,0); //handle
		arg_count = 2;
		opts.steps =0;
	}

	if(strcmp(func, "InternetReadFile") == 0){
		log_val = get_ret(env,4); //lpBuffer
		ret_val = get_ret(env,12);
		arg_count = 4;
	}

	if(arg_count == -1 ){
		printf("invalid use of generic stub no match found for %s",func);
		exit(0);
	}

	int r_esp = cpu->reg[esp];
	r_esp += arg_count*4;
	
	cpu->reg[esp] = r_esp;

	bool nolog = false;

	//i hate spam...
	if(strcmp(func, "GetFileSize") == 0){
		if( (last_GetSizeFHand+1) == log_val || (last_GetSizeFHand+4) == log_val){ 
			if(!gfs_scan_warn){
				printf("%x\tGetFileSize(%x) - open file handle scanning occuring - hiding output...\n",eip_save, log_val);
				gfs_scan_warn = true;
			}
			nolog = true;
		}else{
			gfs_scan_warn = false;
		}
		last_GetSizeFHand = log_val;
	}

	if(!nolog){
		if(log_val == -1){
			printf("%x\t%s() = %x\n", eip_save, func, ret_val );
		}else if(log_val2 == -1){
			printf("%x\t%s(%x) = %x\n", eip_save, func, log_val, ret_val );
		}else{
			printf("%x\t%s(%x, %x) = %x\n", eip_save, func, log_val, log_val2, ret_val );
		}
	}

	if(strcmp(func, "CreateThread") ==0 && (dwCreationFlags == 0 || dwCreationFlags == 0x10000) ){ /* actually should check for bitflags */
		PUSH_DWORD(c, log_val2);
		PUSH_DWORD(c, eip_save);
		emu_cpu_eip_set(c, log_val);
		printf("\tTransferring execution to threadstart...\n");
	}else{
		cpu->reg[eax] = ret_val;
		emu_cpu_eip_set(c, eip_save);
	}
	
	return 0;

}


int32_t	__stdcall new_user_hook_CreateProcessInternalA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	DWORD WINAPI CreateProcessInternal(  
		__in         DWORD unknown1,                              // always (?) NULL  
		__in_opt     LPCTSTR lpApplicationName,  
		__inout_opt  LPTSTR lpCommandLine,  
		__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,  
		__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,  
		__in         BOOL bInheritHandles,  
		__in         DWORD dwCreationFlags,  
		__in_opt     LPVOID lpEnvironment,  
		__in_opt     LPCTSTR lpCurrentDirectory,  
		__in         LPSTARTUPINFO lpStartupInfo,  
		__out        LPPROCESS_INFORMATION lpProcessInformation,  
		__in         DWORD unknown2                               // always (?) NULL
	);
*/
	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_cmdline =0;

	emu_memory_read_dword(mem,stack_addr+8, &p_cmdline);

	if(p_cmdline == 0) emu_memory_read_dword(mem,stack_addr+4, &p_cmdline);

	stack_addr += 12*4;
	cpu->reg[esp] = stack_addr;

	if(p_cmdline !=0){
		struct emu_string *s_text = emu_string_new();
		emu_memory_read_string(mem, p_cmdline, s_text, 255);
		printf("%x\t%s( %s )\n",eip_save, ex->fnname, emu_string_char(s_text) );
		emu_string_free(s_text);
	}else{
		printf("%x\t%s()\n",eip_save,ex->fnname);
	}

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(c, eip_save);
	return 1;
}


int32_t	__stdcall new_user_hook_GlobalAlloc(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	CopyHGLOBAL WINAPI GlobalAlloc(
	  __in  UINT uFlags,
	  __in  SIZE_T dwBytes
	);
*/
	uint32_t flags;
	POP_DWORD(c, &flags);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t baseMemAddress = next_alloc;

	if(size > 0 && size < MAX_ALLOC){
		set_next_alloc(size);
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		printf("%x\tGlobalAlloc(sz=%x) = %x\n", eip_save, size, baseMemAddress);
		free(buf);
	}else{
		printf("%x\tGlobalAlloc(sz=%x) (Ignored size out of range)\n", eip_save, size);
	}

	cpu->reg[eax] = baseMemAddress;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_MapViewOfFile(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
/*
	LPVOID WINAPI MapViewOfFile(  //todo: the return value is the starting address of the mapped view.
	  __in  HANDLE hFileMappingObject,
	  __in  DWORD dwDesiredAccess,
	  __in  DWORD dwFileOffsetHigh,
	  __in  DWORD dwFileOffsetLow,
	  __in  SIZE_T dwNumberOfBytesToMap
	);
*/
	uint32_t eip_save = popd();
	uint32_t h		= popd();
	uint32_t access = popd();
	uint32_t offsetHigh = popd();
	uint32_t offset = popd();
	uint32_t size   = popd();
	uint32_t baseMemAddress = next_alloc;
	void* view = 0;

	//if size=0 then it could be set in CreateFIleMapping. 
	//If was set in CreateFileMapping call and its > opts.fopen_fsize then opts.fopen_fsize is reset
	//if were not in interactive mode, then opts.fopen_fsize == 0 anyway. 
	if(size==0) size = opts.fopen_fsize; 

	if(size > 0 && size < MAX_ALLOC){
		set_next_alloc(size);
		void *buf = malloc(size);
		
		if(opts.interactive_hooks==1) 
			view = MapViewOfFile((HANDLE)h,access,offsetHigh,offset,size);

		if((int)view != 0){
			memcpy(buf,view,size);
		}else{
			if(opts.h_fopen > 0){
				uint32_t bytesRead;
				SetFilePointer(opts.h_fopen, offset, (PLONG)&offsetHigh, FILE_BEGIN);
				uint32_t r = ReadFile(opts.h_fopen, buf, size, &bytesRead, NULL);
			}else{
				memset(buf,0,size); 
			}
		}

		emu_memory_write_block(mem,baseMemAddress,buf, size);

		printf("%x\tMapViewOfFile(h=%x, offset=%x, sz=%x) = %x\n", eip_save, h, offset, size, baseMemAddress);
		free(buf);
		set_ret(baseMemAddress);
	}else{
		printf("%x\tMapViewOfFile(h=%x, offset=%x, sz=%x)\n", eip_save, h, offset, size);
		set_ret(0);
	}

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_URLDownloadToCacheFileA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HRESULT URLDownloadToCacheFile(      
		LPUNKNOWN lpUnkcaller,
		LPCSTR szURL,
		LPTSTR szFileName,
		DWORD cchFileName,
		DWORD dwReserved,
		IBindStatusCallback *pBSC
	);
*/
	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_url =0;
	uint32_t p_fname =0;
	uint32_t bufsz =0;

	emu_memory_read_dword(mem,stack_addr+4, &p_url);
	emu_memory_read_dword(mem,stack_addr+8, &p_fname);
	emu_memory_read_dword(mem,stack_addr+12, &bufsz);

	stack_addr += 6*4;
	cpu->reg[esp] = stack_addr;

	struct emu_string *s_url = emu_string_new();

	emu_memory_read_string(mem, p_url, s_url, 255);
	char* url = emu_string_char(s_url);

	//unicode version now redirected here too..
	//if(url[1] == 0) then its unicode we should use a tmp buf and extract.

	printf("%x\t%s(%s, buf=%x)\n",eip_save, ex->fnname , url, p_fname);

	emu_string_free(s_url);

	char* tmp = "c:\\URLCacheTmpPath.exe";

	//printf("bufsize = %d , pfname = %x\n", bufsz, p_fname);

	if(bufsz > strlen(tmp) ){
		emu_memory_write_block(mem,p_fname, tmp, strlen(tmp));
		emu_memory_write_byte(mem,p_fname + strlen(tmp)+1, 0x00);
	}

	cpu->reg[eax] = 0; // S_OK 
	emu_cpu_eip_set(c, eip_save);
	return 1;
}

int32_t	__stdcall new_user_hook_system(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

	uint32_t stack_addr = cpu->reg[esp]; 
	uint32_t p_url =0;

	emu_memory_read_dword(mem,stack_addr+0, &p_url);

	stack_addr += 1*4;
	cpu->reg[esp] = stack_addr;

	struct emu_string *s_url = emu_string_new();

	emu_memory_read_string(mem, p_url, s_url, 255);

	printf("%x\tsystem(%s)\n",eip_save,  emu_string_char(s_url));

	emu_string_free(s_url);
	cpu->reg[eax] =  0;  
	emu_cpu_eip_set(c, eip_save);
	return 1;
}

int32_t	__stdcall new_user_hook_VirtualAlloc(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	LPVOID WINAPI VirtualAlloc(
	  __in_opt  LPVOID lpAddress,
	  __in      SIZE_T dwSize,
	  __in      DWORD flAllocationType,
	  __in      DWORD flProtect
);


*/
	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t atype;
	POP_DWORD(c, &atype);

	uint32_t flProtect;
	POP_DWORD(c, &flProtect);

	uint32_t baseMemAddress = next_alloc;

	if(size < MAX_ALLOC){
		set_next_alloc(size);
		printf("%x\tVirtualAlloc(base=%x , sz=%x) = %x\n", eip_save, address, size, baseMemAddress);
		if(size < 1024) size = 1024;
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		free(buf);
	}else{
		printf("%x\tVirtualAlloc(sz=%x) (Ignored size out of range)\n", eip_save, size);
	}

	cpu->reg[eax] = baseMemAddress;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_VirtualProtectEx(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	BOOL WINAPI VirtualProtectEx(
	  __in   HANDLE hProcess,
	  __in   LPVOID lpAddress,
	  __in   SIZE_T dwSize,
	  __in   DWORD flNewProtect,
	  __out  PDWORD lpflOldProtect
	);
*/
	uint32_t hProcess;
	POP_DWORD(c, &hProcess);

	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t flNewProtect;
	POP_DWORD(c, &flNewProtect);

	uint32_t lpflOldProtect;
	POP_DWORD(c, &lpflOldProtect);

	printf("%x\tVirtualProtectEx(hProc=%x , addr=%x , sz=%x, prot=%x)\n", eip_save, hProcess, address, size, flNewProtect);
		
	cpu->reg[eax] = 1;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}



//need to find a clean way to have these stubs handle multiple api..this is a start anyway..
//this one can handle logging of 1 or 2 string args..
int32_t	__stdcall new_user_hook_GenericStub2String(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HINTERNET InternetOpenA(
	  __in  LPCTSTR lpszAgent,
	  __in  DWORD dwAccessType,
	  __in  LPCTSTR lpszProxyName,
	  __in  LPCTSTR lpszProxyBypass,
	  __in  DWORD dwFlags
	);

	HINTERNET InternetOpenUrl(
	  __in  HINTERNET hInternet,
	  __in  LPCTSTR lpszUrl,
	  __in  LPCTSTR lpszHeaders,
	  __in  DWORD dwHeadersLength,
	  __in  DWORD dwFlags,
	  __in  DWORD_PTR dwContext
	);

  BOOL SHRegGetBoolUSValue(
	  __in      LPCTSTR pszSubKey,
	  __in_opt  LPCTSTR pszValue,
	  __in      BOOL fIgnoreHKCU,
	  __in      BOOL fDefault
	);

*/
	int arg_count=0;
	int ret_val = 1;
    int log_sarg = -1; //stub support optional logging of 2 string arg
	int log_sarg2 = -1; //stub support optional logging of 2 string args
	int sarg1_len = 255;
	int sarg2_len = 255;

	char* func = ex->fnname;

	if(strcmp(func, "InternetOpenA") ==0 ){
		//printf("InternetOpenA\n");
		log_sarg = get_ret(env,0);  //lpszAgent
		arg_count = 5;
	}

	if(strcmp(func, "InternetOpenUrlA") ==0 ){
		//printf("InternetOpenUrlA\n");
		log_sarg = get_ret(env,4);  //url
		sarg1_len = 500;
		arg_count = 6;
	}

	if(strcmp(func, "SHRegGetBoolUSValueA") ==0 ){
		log_sarg = get_ret(env,0);  //pszSubKey
		log_sarg2 = get_ret(env,4);  //pszValue
		arg_count = 4;
		ret_val = 0;
	}

	if(arg_count==0){
		printf("invalid use of generic stub 2 string no match found for %s",func);
		exit(0);
	}

	int r_esp = c->reg[esp];
	r_esp += arg_count*4;
	
	//printf("adjusting stack by %d prev=%x new=%x\n", arg_count*4, c->reg[esp], r_esp  );
	cpu->reg[esp] = r_esp;

	if(log_sarg == -1){
		printf("%x\t%s()\n", eip_save, func );
	}
	else if(log_sarg2 == -1){
		struct emu_string *s_data = emu_string_new();
	    emu_memory_read_string(mem, log_sarg, s_data, sarg1_len);
		printf("%x\t%s(%s)\n", eip_save, func, emu_string_char(s_data) );
		emu_string_free(s_data);
	}
	else{ //two string args
		struct emu_string *s_1 = emu_string_new();
		struct emu_string *s_2 = emu_string_new();
	    emu_memory_read_string(mem, log_sarg, s_1, sarg1_len);
		emu_memory_read_string(mem, log_sarg2, s_2, sarg2_len);
		printf("%x\t%s(%s , %s)\n", eip_save, func, emu_string_char(s_1), emu_string_char(s_2) );
		emu_string_free(s_1);
		emu_string_free(s_2);
	}


	cpu->reg[eax] = ret_val;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_SetFilePointer(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	
	DWORD WINAPI SetFilePointer(
  __in         HANDLE hFile,
  __in         LONG lDistanceToMove,
  __inout_opt  PLONG lpDistanceToMoveHigh,
  __in         DWORD dwMoveMethod
);


*/
	uint32_t hfile;
	uint32_t lDistanceToMove;
	uint32_t lDistanceToMoveHigh;
	uint32_t dwMoveMethod;

	POP_DWORD(c, &hfile);
	POP_DWORD(c, &lDistanceToMove);
	POP_DWORD(c, &lDistanceToMoveHigh);
	POP_DWORD(c, &dwMoveMethod);

	if(dwMoveMethod > 2 || dwMoveMethod < 0) dwMoveMethod = 3; //this shouldnt happen..
	char* method[4] = {"FILE_BEGIN", "FILE_CURRENT", "FILE_END","UNKNOWN"};

	DWORD rv = 0;
	uint32_t m_hFile = hfile;
	long distanceHigh = 0;
	if(opts.interactive_hooks == 1){
		if((int)opts.h_fopen != 0 && m_hFile < 10) m_hFile = (uint32_t)opts.h_fopen; //from a scanner
		if(lDistanceToMoveHigh != 0){
			rv = SetFilePointer((HANDLE)m_hFile, lDistanceToMove, &distanceHigh ,dwMoveMethod); //doesnt work with fopen handles?
			emu_memory_write_dword(mem, lDistanceToMoveHigh, distanceHigh);
		}else{
			rv = SetFilePointer((HANDLE)m_hFile, lDistanceToMove, 0 ,dwMoveMethod); //doesnt work with fopen handles?
		}
	}

	printf("%x\tSetFilePointer(hFile=%x, dist=%x, %x, %s) = %x\n", eip_save, hfile, lDistanceToMove, lDistanceToMoveHigh, method[dwMoveMethod], rv);

	cpu->reg[eax] = rv;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_ReadFile(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	BOOL WINAPI ReadFile(
	  __in         HANDLE hFile,
	  __out        LPVOID lpBuffer,
	  __in         DWORD nNumberOfBytesToRead,
	  __out_opt    LPDWORD lpNumberOfBytesRead,
	  __inout_opt  LPOVERLAPPED lpOverlapped
	);
*/
	uint32_t hfile;
	uint32_t lpBuffer;
	uint32_t numBytes;
	uint32_t lpNumBytes;
	uint32_t lpOverlap;

	POP_DWORD(c, &hfile);
	POP_DWORD(c, &lpBuffer);
	POP_DWORD(c, &numBytes);
	POP_DWORD(c, &lpNumBytes);
	POP_DWORD(c, &lpOverlap);

	
	//numBytes++;
	uint32_t m_hfile = hfile;
	uint32_t bytesRead=0;
	BOOL rv;

	if( opts.interactive_hooks == 1){
		if( (int)opts.h_fopen != 0 && hfile  < 10 ) m_hfile = (uint32_t)opts.h_fopen; //scanners start at 1 or 4 we let them go with it..
		char* tmp = (char*)malloc(numBytes);
		if(tmp==0){
			printf("\tFailed to allocate %x bytes skipping ReadFile\n",numBytes);
		}else{
			rv = ReadFile( (HANDLE)m_hfile, tmp, numBytes, &bytesRead, 0);
			emu_memory_write_block(mem, lpBuffer,tmp, numBytes);
			if( bytesRead != numBytes) printf("\tReadFile error? numBytes=%x bytesRead=%x rv=%x\n", numBytes, bytesRead, rv);
			free(tmp);
		}
	}

	printf("%x\tReadFile(hFile=%x, buf=%x, numBytes=%x) = %x\n", eip_save, hfile, lpBuffer, numBytes, rv);

	if(lpNumBytes != 0) emu_memory_write_dword(mem, lpNumBytes, numBytes);

	cpu->reg[eax] = 1;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

//scans for first null in emu memory from address. returns emu address of null or limit
uint32_t emu_string_length(uint32_t addr, int scan_limit){
	uint32_t o = addr;
	unsigned char b;

	emu_memory_read_byte(mem, o, &b);
	while(b != 0){
		o++;
		if(o - addr > scan_limit) break;
		emu_memory_read_byte(mem, o, &b);
	}

	return o;
}


int32_t	__stdcall new_user_hook_strstr(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	char *strstr(const char *s1, const char *s2);
*/
	uint32_t s1;
	uint32_t s2;
	uint32_t ret=0;
	POP_DWORD(c, &s1);
	POP_DWORD(c, &s2);
	
	struct emu_string *find = emu_string_new();

	if(s2==0){
		ret = s1;
	}else{
		uint32_t len = emu_string_length(s1, 0x6000);
		emu_memory_read_string(mem, s2, find, 255);

		if(len > 0){
			char* tmp = (char*)malloc(len);
			emu_memory_read_block(mem, s1, tmp, len);
			ret = (int)strstr(tmp, (char*)find->data);
			if(ret != 0){
				uint32_t delta = ret - (int)tmp;
				ret = s1 + delta;
			}
			free(tmp);
		}

	}

	printf("%x\tstrstr(buf=%x, find=\"%s\") = %x\n", eip_save, (int)s1, emu_string_char(find), ret);
	
	emu_string_free(find);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_strtoul(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	unsigned long strtoul(const char *restrict str, char **restrict endptr, int base);
*/
	uint32_t s1;
	uint32_t s2;
	uint32_t base;
	uint32_t ret=0;
	POP_DWORD(c, &s1);
	POP_DWORD(c, &s2);
	POP_DWORD(c, &base);
	
	struct emu_string *arg = emu_string_new();
	uint32_t len = emu_string_length(s1, 0x6000);
	emu_memory_read_string(mem, s1, arg, len);
	ret = strtoul( emu_string_char(arg), NULL, base);

	printf("%x\tstrtoul(buf=%x -> \"%s\", base=%d) = %x\n", eip_save, s1, emu_string_char(arg), base, ret);
	
	emu_string_free(arg);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetTempFileNameA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*	
	UINT WINAPI GetTempFileName(
	  __in   LPCTSTR lpPathName,
	  __in   LPCTSTR lpPrefixString,
	  __in   UINT uUnique,
	  __out  LPTSTR lpTempFileName
	);
*/
	uint32_t s1;
	uint32_t s2;
	uint32_t unique;
	uint32_t out_buf;
	uint32_t ret=0;
	uint32_t org_unique;

	int prefix_len=0;
	int path_len=0;
	char* s_unique = 0;
	char* s_out=0;

	POP_DWORD(c, &s1);
	POP_DWORD(c, &s2);
	POP_DWORD(c, &unique);
	POP_DWORD(c, &out_buf);

	org_unique = unique;

	if(s1==0){
		ret = 0;
		cpu->reg[eax] = 0;
		emu_cpu_eip_set(c, eip_save);
		return 0;
	}

	struct emu_string *path = emu_string_new();
	struct emu_string *prefix = emu_string_new();

	//printf("s1=%x, s2=%x , unique=%x, out_buf=%x\n", s1,s2, unique, out_buf);

	emu_memory_read_string(mem, s1, path, 255);
	emu_memory_read_string(mem, s2, prefix, 3);

	char* s_path = emu_string_char(path);
	char* s_prefix = emu_string_char(prefix);

	if(s_path == 0){
		s_path = (char*)malloc(10); //memleak
		strcpy(s_path,"");
	}else{
		path_len = strlen(s_path);
	}

	if(s_prefix == 0){
		s_prefix = (char*)malloc(10); //memleak
		strcpy(s_prefix,"");
	}else{
		prefix_len = strlen(s_prefix);
	}

    if(unique==0) unique = 0xBAAD;
	printf("GetTempFileNameA broken fix me\n");
	return 0;
//	if(asprintf(&s_unique, "%X", unique) == -1) return -1;

	uint32_t slen = path_len + prefix_len + strlen(s_unique) + 15;

	if(slen > 255){
		ret = 0;
	}else{
		ret = unique;
		s_out = (char*)malloc(300);
		sprintf(s_out, "%s\\%s%s.TMP", s_path, s_prefix, s_unique);
		emu_memory_write_block(mem, out_buf, s_out, strlen(s_out));
	}
	
	printf("%x\tGetTempFileNameA(path=%s, prefix=%x (%s), unique=%x, buf=%x) = %X\n", eip_save, 
			 s_path, s2, s_prefix, org_unique, out_buf, ret);

	if(ret!=0) printf("\t Path = %s\n", s_out);

	if(s_out != 0) free(s_out);
	free(s_unique);
	emu_string_free(path);
	emu_string_free(prefix);

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_LoadLibrary(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);
    struct emu_string *dllstr = emu_string_new();

	char* func = ex->fnname;

	int i=0;
	int found_dll = 0;
	uint32_t eip_save;
	uint32_t dllname_ptr;
	uint32_t dummy;

/* 
   LoadLibraryA(LPCTSTR lpFileName); 
   LoadLibraryExA(LPCTSTR lpFileName, hFile, flags)
*/

	POP_DWORD(c, &eip_save);
    POP_DWORD(c, &dllname_ptr);
    	
	if(strcmp(func, "LoadLibraryExA") ==0 ){
		POP_DWORD(c, &dummy);
		POP_DWORD(c, &dummy);
	}

    emu_memory_read_string(mem, dllname_ptr, dllstr, 256);
	char *dllname = emu_string_char(dllstr);

	for (i=0; env->env.win->loaded_dlls[i] != NULL; i++)
	{
		if (stricmp(env->env.win->loaded_dlls[i]->dllname, dllname) == 0)
		{
			cpu->reg[eax] = env->env.win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
			break;
		}
	}
	
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(env->env.win, dllname) == 0)
        {
            cpu->reg[eax] = env->env.win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
        }
        else
        {
            cpu->reg[eax] = 0;
        }
	}

	printf("%x\t%s(%s)\n",eip_save, func, dllname);
	if(found_dll == 0) printf("\tNot found\n");

	emu_string_free(dllstr);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetModuleFileNameA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	DWORD WINAPI GetModuleFileName(
	  __in_opt  HMODULE hModule,
	  __out     LPTSTR lpFilename,
	  __in      DWORD nSize
	);
*/
	uint32_t hmod;
	POP_DWORD(c, &hmod);

	uint32_t lpfname;
	POP_DWORD(c, &lpfname);

	uint32_t nsize;
	POP_DWORD(c, &nsize);

	int i=0;
	char ret[255]={0} ;

	if(hmod==0){
		strcpy(ret,"c:\\Program Files\\scdbg\\parentApp.exe");
	}else{
		for (i=0; env->env.win->loaded_dlls[i] != NULL; i++){
			if (env->env.win->loaded_dlls[i]->baseaddr == hmod){
				sprintf(ret, "c:\\Windows\\System32\\%s", env->env.win->loaded_dlls[i]->dllname);
				break;
			}
		}
	}

	i = strlen(ret);

	printf("%x\tGetModuleFilenameA(hmod=%x, buf=%x, sz=%x) = %s\n",eip_save, hmod, lpfname, nsize, ret);

	if(i > 0 && i < nsize){
		emu_memory_write_block(mem, lpfname, &ret, i);
	} 

	cpu->reg[eax] =  i;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_DialogBoxIndirectParamA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	INT_PTR WINAPI DialogBoxIndirectParam(
	  __in_opt  HINSTANCE hInstance,
	  __in      LPCDLGTEMPLATE hDialogTemplate,
	  __in_opt  HWND hWndParent,
	  __in_opt  DLGPROC lpDialogFunc,
	  __in      LPARAM dwInitParam
	);
*/
	uint32_t hmod;
	POP_DWORD(c, &hmod);

	uint32_t hdlg;
	POP_DWORD(c, &hdlg);

	uint32_t hwnd;
	POP_DWORD(c, &hwnd);

	uint32_t lpproc;
	POP_DWORD(c, &lpproc);

	uint32_t param;
	POP_DWORD(c, &param);

	printf("%x\tDialogBoxIndirectParamA(hmod=%x, hdlg=%x, hwnd=%x, proc=%x, param=%x)\n",
		eip_save, hmod, hdlg, hwnd, lpproc, param);

	cpu->reg[eax] = 1;

	if( lpproc != 0 ){
		PUSH_DWORD(c, param);
		PUSH_DWORD(c, eip_save);
		emu_cpu_eip_set(c, lpproc);
		printf("\tTransferring execution to DialogProc...\n");
	}else{
		emu_cpu_eip_set(c, eip_save);
	}

	return 0;
}

int32_t	__stdcall new_user_hook_ZwQueryVirtualMemory(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	NTSYSAPI NTSTATUS NTAPI	ZwQueryVirtualMemory(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation,
		IN ULONG MemoryInformationLength,
		OUT PULONG ReturnLength OPTIONAL
	);

	typedef struct _MEMORY_BASIC_INFORMATION {
	  PVOID  BaseAddress;
	  PVOID  AllocationBase;
	  ULONG  AllocationProtect;
	  ULONG  RegionSize;
	  ULONG  State;
	  ULONG  Protect;
	  ULONG  Type;
	} MEMORY_BASIC_INFORMATION;

    http://doxygen.reactos.org/d8/d6b/ndk_2mmfuncs_8h_a408860f675a0b9f1c8f3e84312291a0e.html#a408860f675a0b9f1c8f3e84312291a0e
	http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtQueryVirtualMemory.html
	http://forum.sysinternals.com/changing-page-permissions_topic6101_page2.html

    MEMORY_INFORMATION_CLASS Enumerator:  http://doxygen.reactos.org/d9/da5/ndk_2mmtypes_8h_a6c7d439c9a9d33ae4a117d7bfd9ae2d6.html#a6c7d439c9a9d33ae4a117d7bfd9ae2d6
		MemoryBasicInformation   
		MemoryWorkingSetList   
		MemorySectionName          //get file name from memorymapped file (using only fhandle) ? unicode result?
		MemoryBasicVlmInformation   
		 

*/

	char* mic[5] = {"BasicInfo", "WorkSet", "SectName", "BasicVlm", "Unknown"}; 
	
	uint32_t hproc;
	POP_DWORD(c, &hproc);

	uint32_t base;
	POP_DWORD(c, &base);

	uint32_t mem_info_class;
	POP_DWORD(c, &mem_info_class);

	uint32_t mem_info;
	POP_DWORD(c, &mem_info);

	uint32_t mem_info_len;
	POP_DWORD(c, &mem_info_len);

	uint32_t ret_len;
	POP_DWORD(c, &ret_len);
	
	uint32_t safe_mic = mem_info_class;
	if( mem_info_class > 3 ) safe_mic = 4;
			
	//TODO: copy the proper info to *meminfo based on class requested and fill out rlen if not null.
	//      honestly though how often are we going to see this...not gonna bust a nut for undocumented rarely used api..
	printf("%x\tZwQueryVirtualMemory(pid=%x, base=%x, cls=%x (%s), buf=%x, sz=%x, *retval=%x)\n",
		eip_save, hproc, base, mem_info_class, mic[safe_mic], mem_info, mem_info_len, ret_len);

	if(mem_info_class == 2){ //sectname
		char* sectname = "\\Device\\HarddiskVolume1\\parent_file.doc"; //technically this should be unicode..but they will convert it anyway so skip that shit
		int sl = strlen(sectname);
		if(sl < mem_info_len){
			emu_memory_write_block(mem, mem_info, sectname, sl);
			if(ret_len != 0) emu_memory_write_dword(mem, ret_len, sl);
		}else{
			printf("\tBuffer not large enough to embed Section Name\n");
		}
	}

	cpu->reg[eax] = 1;	 
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetEnvironmentVariableA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	DWORD WINAPI GetEnvironmentVariable(
	  __in_opt   LPCTSTR lpName,
	  __out_opt  LPTSTR lpBuffer,
	  __in       DWORD nSize
	);	
*/
	
	uint32_t lpname;
	POP_DWORD(c, &lpname);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t size;
	POP_DWORD(c, &size);

	struct emu_string *var_name = emu_string_new();
	emu_memory_read_string(mem, lpname, var_name, 256);
	char* var = (char*)var_name->data;
	
	char out[256]={0}; 

	if(stricmp(var, "ProgramFiles") == 0 ) strcpy(out, "C:\\Program Files");
	if(stricmp(var, "TEMP") == 0 )         strcpy(out, "C:\\Windows\\Temp");
	if(stricmp(var, "TMP") == 0 )          strcpy(out, "C:\\Windows\\Temp");
	if(stricmp(var, "WINDIR") == 0 )       strcpy(out, "C:\\Windows");

	int sl = strlen(out);

	if(sl < size) emu_memory_write_block(mem, buf, out, sl);
		
	printf("%x\tGetEnvironmentVariableA(name=%s, buf=%x, size=%x) = %s\n", eip_save, var, buf, size, out );

	cpu->reg[eax] =  sl;	 
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_VirtualAllocEx(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	LPVOID WINAPI VirtualAllocEx(
	  __in      HANDLE hProcess,
	  __in_opt  LPVOID lpAddress,
	  __in      SIZE_T dwSize,
	  __in      DWORD flAllocationType,
	  __in      DWORD flProtect
);


*/
	uint32_t hproc;
	POP_DWORD(c, &hproc);

	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t atype;
	POP_DWORD(c, &atype);

	uint32_t flProtect;
	POP_DWORD(c, &flProtect);

	uint32_t baseMemAddress = next_alloc;

	if(size < MAX_ALLOC){
		set_next_alloc(size);
		printf("%x\tVirtualAllocEx(pid=%x, base=%x , sz=%x) = %x\n", eip_save, hproc, address, size, baseMemAddress);
		if(size < 1024) size = 1024;
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		free(buf);
	}else{
		printf("%x\tVirtualAllocEx(pid=%x, sz=%x) (Ignored size out of range)\n", eip_save, hproc, size);
	}

	cpu->reg[eax] = baseMemAddress;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_WriteProcessMemory(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	BOOL WINAPI WriteProcessMemory( //we assume its a process injection with base=VirtuaAllocEx so we embed there
	  __in   HANDLE hProcess,
	  __in   LPVOID lpBaseAddress,
	  __in   LPCVOID lpBuffer,
	  __in   SIZE_T nSize,
	  __out  SIZE_T *lpNumberOfBytesWritten
	);
*/

	uint32_t hproc;
	POP_DWORD(c, &hproc);

	uint32_t address;
	POP_DWORD(c, &address);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t BytesWritten;
	POP_DWORD(c, &BytesWritten);

	printf("%x\tWriteProcessMemory(pid=%x, base=%x , buf=%x, sz=%x, written=%x)\n", eip_save, hproc, address, buf, size, BytesWritten);

	if(size < MAX_ALLOC){
		unsigned char* tmp = (unsigned char*)malloc(size);
		emu_memory_read_block(mem, buf, tmp, size);
		
		if(opts.show_hexdumps){
			int display_size = size;
			if(display_size > 300){ 
				printf("\tShowing first 300 bytes...\n");
				display_size = 300;
			}
			hexdump(tmp, display_size);
		}
		 
		emu_memory_write_block(mem, address, tmp, size);
		if(BytesWritten != 0) emu_memory_write_dword(mem, BytesWritten, size);
	}else{
		printf("\tSize > MAX_ALLOC (%x) ignoring...", MAX_ALLOC);
	}

	cpu->reg[eax] = 1;
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_CreateRemoteThread(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	HANDLE WINAPI CreateRemoteThread(
	  __in   HANDLE hProcess,
	  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	  __in   SIZE_T dwStackSize,
	  __in   LPTHREAD_START_ROUTINE lpStartAddress,
	  __in   LPVOID lpParameter,
	  __in   DWORD dwCreationFlags,
	  __out  LPDWORD lpThreadId
	);
*/

	uint32_t hproc   = get_ret(env, 0);
	uint32_t address = get_ret(env, 12);
	uint32_t arg     = get_ret(env, 16);
	uint32_t flags   = get_ret(env, 20);
	uint32_t id      = get_ret(env, 24);

	int r_esp = cpu->reg[esp];
	r_esp += 7*4;
	cpu->reg[esp] = r_esp;

	printf("%x\tCreateRemoteThread(pid=%x, addr=%x , arg=%x, flags=%x, *id=%x)\n", eip_save, hproc, address, arg, flags, id);

	if((flags == 0 || flags == 0x10000) ){ /* actually should check for bitflags */
		PUSH_DWORD(c, arg);
		PUSH_DWORD(c, eip_save);
		emu_cpu_eip_set(c, address);
		printf("\tTransferring execution to threadstart...\n");
	}else{
		cpu->reg[eax] = 0x222;
		emu_cpu_eip_set(c, eip_save);
	}

	return 0;
}


int32_t	__stdcall new_user_hook_MultiByteToWideChar(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
	Copyint MultiByteToWideChar(
	  __in   UINT CodePage,
	  __in   DWORD dwFlags,
	  __in   LPCSTR lpMultiByteStr,
	  __in   int cbMultiByte,
	  __out  LPWSTR lpWideCharStr,
	  __in   int cchWideChar
	);

*/

	uint32_t cp      = get_ret(env, 0);
	uint32_t flags   = get_ret(env, 4);
	uint32_t src     = get_ret(env, 8);
	uint32_t size    = get_ret(env, 12);
	uint32_t dst     = get_ret(env, 16);
	uint32_t dstsz   = get_ret(env, 20);

	int r_esp = cpu->reg[esp];
	r_esp += 6*4;
	cpu->reg[esp] = r_esp;

	struct emu_string *s_src = emu_string_new();
	emu_memory_read_string(mem, src, s_src, 500);
	char* s = (char*)s_src->data;

	if(opts.verbose > 0){
		printf("%x\tMultiByteToWideChar(cp=%x, fl=%x , src=%x, sz=%x, dst=%x, dstsz=%x)\n", eip_save, cp, flags, src, size, dst,dstsz);
		printf("\t%x -> %s\n", src, s);
	}else{
		printf("%x\tMultiByteToWideChar(%s)\n", eip_save, s);
	}

	int retval = (strlen(s) * 2);

	if(dst != 0 && dstsz!=0 && dstsz < MAX_ALLOC && dstsz >= retval){ 
		//just write the ascii string to the unicode buf, they are probably just gonna 
		//pass it back to our hook. work an experiment to see if it causes problems or not
		emu_memory_write_block(mem, dst, s_src->data, strlen(s));
	}

	/*
	  why make more work for myself?
	  int i=0;
	  if(dst != 0 && dstsz!=0 && dstsz < MAX_ALLOC && dstsz >= retval){ 
		char* tmp = (char*)malloc(dstsz+100);
		memset(tmp,0,dstsz+100);

		for(i=0;i<strlen(s);i++){
			if(i > dstsz){ retval = 0; break;}
			tmp[i*2] = s[i];
		}

		emu_memory_write_block(mem, dst, tmp, retval);

	}*/
		
	cpu->reg[eax] = retval;
	emu_cpu_eip_set(c, eip_save);
	 
	return 0;
}

int32_t	__stdcall new_user_hook_CreateFileW(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{

	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);

/*
HANDLE CreateFile(
  LPCTSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
);
*/

	uint32_t p_filename;
	POP_DWORD(c, &p_filename);
    struct emu_string *filename = emu_string_new();
	emu_memory_read_string(emu_memory_get(env->emu), p_filename, filename, 256);

	uint32_t desiredaccess;
	POP_DWORD(c, &desiredaccess);

	uint32_t sharemode;
	POP_DWORD(c, &sharemode);

	uint32_t securityattr;
	POP_DWORD(c, &securityattr);

    uint32_t createdisp;
	POP_DWORD(c, &createdisp);

	uint32_t flagsandattr;
	POP_DWORD(c, &flagsandattr);

	uint32_t templatefile;
	POP_DWORD(c, &templatefile);

//	uint32_t returnvalue;

	printf("CreateFileW do stuff\n");


	emu_string_free(filename);

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(c, eip_save);

	return 0;
}

int32_t	__stdcall new_user_hook_URLDownloadToFileA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
/*
HRESULT URLDownloadToFile(
  LPUNKNOWN pCaller,
  LPCTSTR szURL,
  LPCTSTR szFileName,
  DWORD dwReserved,
  LPBINDSTATUSCALLBACK lpfnCB
);
*/
	uint32_t p_caller;
	POP_DWORD(c, &p_caller);

	uint32_t p_url;
	POP_DWORD(c, &p_url);

    struct emu_string *url = emu_string_new();
	emu_memory_read_string(c->mem, p_url, url, 512);

	uint32_t p_filename;
	POP_DWORD(c, &p_filename);

	struct emu_string *filename = emu_string_new();
	emu_memory_read_string(c->mem, p_filename, filename, 512);

	uint32_t reserved;
	POP_DWORD(c, &reserved);

	uint32_t statuscallbackfn;
	POP_DWORD(c, &statuscallbackfn);

	uint32_t returnvalue=0;
	printf("%x\tURLDownloadToFile(%s, %s)\n",eip_save, emu_string_char(url), emu_string_char(filename));

	cpu->reg[eax] = returnvalue;

	emu_string_free(url);
	emu_string_free(filename);
    emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_execv(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);

	/*
	intptr_t _execv( 
	   const char *cmdname,
	   const char *const *argv 
	);
	intptr_t _wexecv( 
	   const wchar_t *cmdname,
	   const wchar_t *const *argv 
	);
	*/

	uint32_t p_cmdname;
	POP_DWORD(c, &p_cmdname);

	struct emu_string *cmdname = emu_string_new();
	emu_memory_read_string(c->mem, p_cmdname, cmdname, 512);

	uint32_t p_argv;
	POP_DWORD(c, &p_argv);

	printf("%x\texecv(%s, %x)\n", eip_save, emu_string_char(cmdname), p_argv);

	emu_string_free(cmdname);
    emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_fclose(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*
	int _fcloseall( void );
	int fclose( FILE *stream );
	*/
	uint32_t p_stream;
	MEM_DWORD_READ(c, c->reg[esp], &p_stream);

	cpu->reg[eax] = 0;

	printf("%x\tfclose(h=%x)\n",eip_save, (int)p_stream);

	if( opts.interactive_hooks == 0 ){
		cpu->reg[eax] = 0x4711;
	}else{
    	cpu->reg[eax] = fclose((FILE*)p_stream);
	}
	
    emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_fopen(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*
	FILE *fopen( const char *filename, const char *mode );
	FILE *_wfopen( const wchar_t *filename, const wchar_t *mode );
	*/
	uint32_t p_filename;
	MEM_DWORD_READ(c, c->reg[esp], &p_filename);

	struct emu_string *filename = emu_string_new();
	emu_memory_read_string(c->mem, p_filename, filename, 512);
	
	uint32_t p_mode;
	MEM_DWORD_READ(c, c->reg[esp]+4, &p_mode);
	struct emu_string *mode = emu_string_new();
	emu_memory_read_string(c->mem, p_mode, mode, 512);
	
	if( opts.interactive_hooks == 0){
		printf("%x\tfopen(%s, %s) = %x\n", eip_save, emu_string_char(filename), emu_string_char(mode), 0x4711);
		cpu->reg[eax] = 0x4711;
	}else{
		char* localfile = SafeTempFile();
		FILE *f = fopen(localfile,"w");
		printf("%x\tfopen(%s) = %x\n", eip_save, filename, (int)f);
		printf("\tInteractive mode local file: %s\n", localfile);
		free(localfile);
		cpu->reg[eax] = (int)f; 
	}

	emu_string_free(filename);
	emu_string_free(mode);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_fwrite(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	logDebug(env->emu, "Hook me Captain Cook!\n");
	logDebug(env->emu, "%s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*
size_t fwrite( const void *buffer, size_t size, size_t count, FILE *stream );
*/
	uint32_t p_buffer;
	MEM_DWORD_READ(c, c->reg[esp], &p_buffer);
	
	uint32_t size;
	MEM_DWORD_READ(c, (c->reg[esp]+4), &size);

	uint32_t count;
	MEM_DWORD_READ(c, (c->reg[esp]+8), &count);
	
	uint32_t len = size * count;

	uint32_t MAX_ALLOC = 0x900000;
	if(len > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		len = MAX_ALLOC; //dzzie
	}

	unsigned char *buffer = (unsigned char*)malloc(len);
	emu_memory_read_block(emu_memory_get(env->emu), p_buffer, buffer, len);

	uint32_t p_stream;
	MEM_DWORD_READ(c, c->reg[esp]+12, &p_stream);
		
	printf("%x\tfwrite(h=%x, sz=%x, buf=%x)\n", eip_save, (int)p_stream, size*count, p_buffer);
	
	if(opts.show_hexdumps && buffer != 0 && size > 0 && count > 0){
		int display_size = size*count;
		if(display_size > 300){ 
			printf("Showing first 300 bytes...\n");
			display_size = 300;
		}
		hexdump(buffer, display_size );
	}

	uint32_t retval = size*count;
	cpu->reg[eax] = retval;

	if(opts.interactive_hooks != 0 ){
		retval = fwrite(buffer, size, count, (FILE*)p_stream);
	}
	
	cpu->reg[eax] = retval;
	free(buffer);
    emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook__lcreat(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*
	LONG _lcreat(
	  LPCSTR lpszFileName,
	  int fnAttribute
	);
	*/
	uint32_t p_filename;
	POP_DWORD(c, &p_filename);
	struct emu_string *filename = emu_string_new();
	emu_memory_read_string(emu_memory_get(env->emu), p_filename, filename, 256);

	uint32_t fnAttribute;
	POP_DWORD(c, &fnAttribute);

	char* fname = emu_string_char(filename);

	printf("%x\t_lcreate(%s)\n",eip_save, fname);
	
	uint32_t handle = 0;

	if(opts.interactive_hooks != 0){
		char *localfile = SafeTempFile();
		FILE *f = fopen(localfile,"w");
		printf("\tInteractive mode local file: %s\n", localfile);
		free(localfile);
		handle = (int)f;
	}else{
		handle = get_fhandle();
	}

	cpu->reg[eax] = handle;

	emu_string_free(filename);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook__lclose(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
/*
HFILE _lclose(
    HFILE hFile	// handle to file to close
   ); 
*/
	uint32_t file;
	POP_DWORD(c, &file);

	printf("%x\t_lclose(h=%x)\n",eip_save,file);
	cpu->reg[eax] = 0;

	if( opts.interactive_hooks != 0 ){
		cpu->reg[eax] = fclose((FILE*)file);
	}

	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook__lwrite(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*
	LONG _lwrite(
	  HFile hFile,
	  LPCSTR lpBuffer,
	  UINT cbWrite
	);
	*/
	uint32_t file;
	POP_DWORD(c, &file);

	uint32_t p_buffer;
	POP_DWORD(c, &p_buffer);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t MAX_ALLOC = 0x900000;
	if(size > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		size = MAX_ALLOC; //dzzie
	}

	unsigned char *buffer = (unsigned char*)malloc(size);
	emu_memory_read_block(emu_memory_get(env->emu), p_buffer, buffer, size);
	
	printf("%x\t_lwrite(h=%x, buf=%x)\n",eip_save, file, p_buffer);

	if(opts.show_hexdumps && buffer != 0 && size > 0) hexdump((unsigned char*)buffer, size);

	cpu->reg[eax] = size;

	if(opts.interactive_hooks != 0 ){
		int r = fwrite((void*)buffer, 1, size, (FILE*)file);
		set_ret(r);
	}

	free(buffer);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetTempPathA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*
	DWORD WINAPI GetTempPath(
	  __in   DWORD nBufferLength,
	  __out  LPTSTR lpBuffer
	);
	*/
	uint32_t bufferlength;
	POP_DWORD(c, &bufferlength);

	uint32_t p_buffer;
	POP_DWORD(c, &p_buffer);

	static char *path = "c:\\%TEMP%\\";
	emu_memory_write_block(emu_memory_get(env->emu), p_buffer, path, strlen(path));
	set_ret(strlen(path));

	printf("%x\tGetTempPath(len=%x, buf=%x)\n",eip_save, bufferlength, p_buffer);

	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetTickCount(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	uint32_t tickcount = rand();
	set_ret(tickcount);
	printf("%x\tGetTickCount() = %x\n", eip_save, tickcount);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook__hwrite(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	return new_user_hook__lwrite(env, ex);
}

int32_t	__stdcall new_user_hook_WinExec(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);

	/* UINT WINAPI WinExec( LPCSTR lpCmdLine, UINT uCmdShow);*/
	uint32_t p_cmdline;
	POP_DWORD(c, &p_cmdline);

	struct emu_string *cmdstr = emu_string_new();
	emu_memory_read_string(emu_memory_get(env->emu), p_cmdline, cmdstr, 1256);

	uint32_t show;
	POP_DWORD(c, &show);
	
	uint32_t returnvalue = 32;
	printf("%x\tWinExec(%s)\n",eip_save, emu_string_char(cmdstr));
	emu_string_free(cmdstr);
	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_Sleep(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	uint32_t dwMilliseconds;
	POP_DWORD(c, &dwMilliseconds);
	set_ret(0);
	printf("%x\tSleep(0x%x)\n", eip_save, dwMilliseconds);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_DeleteFileA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

	uint32_t filename;
	POP_DWORD(c, &filename);

	struct emu_string *s_filename = emu_string_new();
	emu_memory_read_string(mem, filename, s_filename, 256);
	printf("%x\tDeleteFileA(%s)\n",eip_save, emu_string_char(s_filename) );
	set_ret(0);
	emu_string_free(s_filename);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_ExitProcess(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/* VOID WINAPI ExitProcess(UINT uExitCode); */
	/* VOID ExitThread(DWORD dwExitCode); */
	uint32_t exitcode;
	POP_DWORD(c, &exitcode);
	printf("%x\t%s(%i)\n", eip_save, ex->fnname, exitcode);
	set_ret(0);
	emu_cpu_eip_set(c, eip_save);
	opts.steps = 0;
	return 0;
}


int32_t	__stdcall new_user_hook_CloseHandle(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/* BOOL CloseHandle( HANDLE hObject);*/
	uint32_t object;
	POP_DWORD(c, &object);
	set_ret(1);
	printf("%x\tCloseHandle(%x)\n", eip_save,(int)object);
	if(opts.interactive_hooks == 1){
		set_ret( CloseHandle((HANDLE)object) );
	}
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_CreateFileA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
	
	/*
		HANDLE CreateFile(
		  LPCTSTR lpFileName,
		  DWORD dwDesiredAccess,
		  DWORD dwShareMode,
		  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		  DWORD dwCreationDisposition,
		  DWORD dwFlagsAndAttributes,
		  HANDLE hTemplateFile
		);
	*/
    struct emu_string *filename = popstring();
	uint32_t desiredaccess = popd();
	uint32_t sharemode = popd();
	uint32_t securityattr = popd();
    uint32_t createdisp = popd();
	uint32_t flagsandattr = popd();
	uint32_t templatefile = popd();

	char *localfile = 0;

	if( opts.CreateFileOverride ){ 
		set_ret((int)opts.h_fopen);
	}else{
		if(opts.interactive_hooks == 1 ){
			localfile = SafeTempFile();
			//FILE *f = fopen(localfile,"w");
			HANDLE f = CreateFile(localfile,GENERIC_READ | GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0); 
			set_ret((int)f);
		}else{
			set_ret( get_fhandle() );
		}
	}
	
	printf("%x\t%s(%s) = %x\n", eip_save, ex->fnname, emu_string_char(filename), cpu->reg[eax]  );

	if(!opts.CreateFileOverride && opts.interactive_hooks) printf("\tInteractive mode local file %s\n", localfile);

	emu_string_free(filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_CreateProcessA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	struct emu_memory *m = emu_memory_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
/*BOOL CreateProcess( 
  LPCWSTR pszImageName, 
  LPCWSTR pszCmdLine, 
  LPSECURITY_ATTRIBUTES psaProcess, 
  LPSECURITY_ATTRIBUTES psaThread, 
  BOOL fInheritHandles, 
  DWORD fdwCreate, 
  LPVOID pvEnvironment, 
  LPWSTR pszCurDir, 
  LPSTARTUPINFOW psiStartInfo, 
  LPPROCESS_INFORMATION pProcInfo
);*/
	uint32_t p_imagename;
	POP_DWORD(c, &p_imagename);

	struct emu_string *imagename = emu_string_new();
	emu_memory_read_string(m, p_imagename, imagename, 1024);

	uint32_t p_cmdline;
	POP_DWORD(c, &p_cmdline);

	struct emu_string *command = emu_string_new();
	emu_memory_read_string(m, p_cmdline, command, 1024);

	uint32_t p_process;
	POP_DWORD(c, &p_process);

	uint32_t p_thread;
	POP_DWORD(c, &p_thread);

	uint32_t inherithandles;
	POP_DWORD(c, &inherithandles);

	uint32_t create;
	POP_DWORD(c, &create);

	uint32_t environment;
	POP_DWORD(c, &environment);

	uint32_t cwd;
	POP_DWORD(c, &cwd);

	uint32_t p_startinfo;
	POP_DWORD(c, &p_startinfo);

	STARTUPINFO *si = (STARTUPINFO*)malloc(sizeof(STARTUPINFO));
	memset(si, 0, sizeof(STARTUPINFO));

	emu_memory_read_dword(m, p_startinfo + 14 * 4, (uint32_t *)&si->hStdInput);
	emu_memory_read_dword(m, p_startinfo + 15 * 4, (uint32_t *)&si->hStdOutput);
	emu_memory_read_dword(m, p_startinfo + 16 * 4, (uint32_t *)&si->hStdError);

	uint32_t p_procinfo;
	POP_DWORD(c, &p_procinfo);

	PROCESS_INFORMATION *pi = (PROCESS_INFORMATION*)malloc(sizeof(PROCESS_INFORMATION));
	memset(pi, 0, sizeof(PROCESS_INFORMATION));

	pi->hProcess = (HANDLE)4713;
	pi->hThread = (HANDLE)4714;
	pi->dwProcessId = 4711;
	pi->dwThreadId = 4712;

	emu_memory_write_dword(m, p_procinfo+0*4, (uint32_t)pi->hProcess);
	emu_memory_write_dword(m, p_procinfo+1*4, (uint32_t)pi->hThread);
	emu_memory_write_dword(m, p_procinfo+2*4, pi->dwProcessId);
	emu_memory_write_dword(m, p_procinfo+3*4, pi->dwThreadId);
	emu_memory_write_dword(m, p_procinfo+0*4, (uint32_t)pi->hProcess);
	emu_memory_write_dword(m, p_procinfo+1*4, (uint32_t)pi->hThread);
	emu_memory_write_dword(m, p_procinfo+2*4, pi->dwProcessId);
	emu_memory_write_dword(m, p_procinfo+3*4, pi->dwThreadId);

	char* pszCmdLine = emu_string_char(command);
	char* pszImageName = emu_string_char(imagename);

	if(p_imagename == 0 && pszCmdLine[0] == 0){
		//some shellcode uses the function prolog of CreateProcess to put stack inline..
		struct emu_string *cmd = emu_string_new();
		emu_memory_read_string(mem, cpu->reg[ebp] , cmd, 255);
		printf("%x\tCreateProcessA( %s ) = 0x1269 (ebp)\n",eip_save, (char*)cmd->data);
		emu_string_free(cmd);
	}else{
		printf("%x\tCreateProcessA( %s, %s ) = 0x1269\n",eip_save, pszCmdLine, pszImageName );
	}

	set_ret(0x1269);
	emu_string_free(imagename);
	emu_string_free(command);
	free(pi);
	free(si);

	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_GetVersion(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/* DWORD WINAPI GetVersion(void); */
	uint32_t version = 0xa280105;
	set_ret(version);
	printf("%x\tGetVersion()\n", eip_save);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetProcAddress(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{ /* FFARPROC WINAPI GetProcAddress(  HMODULE hModule,  LPCSTR lpProcName);*/
	uint32_t eip_save = popd();
	uint32_t module = popd();
	struct emu_string *procname = popstring();

	uint32_t ordial = 0;
	uint32_t index  = 0;
	int i;
	bool invalid = false;
	set_ret(0); //set default value of 0 (not found) //dzzie		

	for ( i=0; env->env.win->loaded_dlls[i] != NULL; i++ )
	{
		struct emu_env_w32_dll* dll = env->env.win->loaded_dlls[i];

		if ( dll->baseaddr == module )
		{
			if( procname->size == 0 ){ //either an error or an ordial
				ordial = procname->emu_offset;
				struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_ordial, (void *)ordial);
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}else{
				struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnname, (void *)emu_string_char(procname));
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
				//logDebug(env->emu, "found %s at addr %08x\n",emu_string_char(procname), dll->baseaddr + hook->hook.win->virtualaddr );
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}
		}	
	}

	if(ordial==0){
		printf("%x\tGetProcAddress(%s)\n",eip_save, emu_string_char(procname));
	}else{
		printf("%x\tGetProcAddress(%s.0x%x) - ordial\n",eip_save, dllFromAddress(module), ordial);
	}

	if(module == 0 || cpu->reg[eax] == 0 ) printf("\tLookup not found: module base=%x dllName=%s\n", module, dllFromAddress(module) );  

	emu_string_free(procname);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_GetSystemDirectoryA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/* UINT GetSystemDirectory(   LPTSTR lpBuffer,   UINT uSize ); */
	uint32_t p_buffer;
	POP_DWORD(c, &p_buffer);
	uint32_t size;
	POP_DWORD(c, &size);
	static char *sysdir = "c:\\WINDOWS\\system32";
	emu_memory_write_block(emu_memory_get(env->emu), p_buffer, sysdir, 20);
	set_ret(19);
	printf("%x\tGetSystemDirectoryA( c:\\windows\\system32\\ )\n",eip_save);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_malloc(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*void *malloc( size_t size );*/
	uint32_t size;
	POP_DWORD(c, &size);
	PUSH_DWORD(c, size);

	if(size > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		size = MAX_ALLOC; //dzzie
	}

	uint32_t addr;
	if (emu_memory_alloc(c->mem, &addr, size) == -1)
		set_ret(0);
	else
		set_ret(addr);

	printf("%x\tmalloc(%x)\n",eip_save,size);	
    emu_cpu_eip_set(c, eip_save);
	return 0;
}



int32_t	__stdcall new_user_hook_memset(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*	void *memset(   void* dest,    int c,    size_t count );*/
	uint32_t dest;
	POP_DWORD(c, &dest);
	
	uint32_t writeme;
	POP_DWORD(c, &writeme);
	
	uint32_t size;
	POP_DWORD(c, &size);

	PUSH_DWORD(c, size);     /* not a bug, apparently ntdll.memset is cdecl not stdcall doesnt clean up stack */
	PUSH_DWORD(c, writeme);
	PUSH_DWORD(c, dest);

	printf("%x\tmemset(buf=%x, c=%x, sz=%x)\n",eip_save,dest,writeme,size);
	set_ret(dest);
    emu_cpu_eip_set(c, eip_save);
	return 0;

}

int32_t	__stdcall new_user_hook_SetUnhandledExceptionFilter(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save;
	POP_DWORD(cpu, &eip_save);

	/*LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);*/

	uint32_t lpfilter;
	POP_DWORD(cpu, &lpfilter);

	set_ret(0x7C81CDDA);
	printf("%x\tSetUnhandledExceptionFilter(%x)\n",eip_save,lpfilter);

	uint32_t seh = 0;
	disable_mm_logging = true;
	if(emu_memory_read_dword( mem, FS_SEGMENT_DEFAULT_OFFSET, &seh) != -1){
		emu_memory_write_dword( mem, seh+4, lpfilter);
	}
	disable_mm_logging = false;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_WaitForSingleObject(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*DWORD WINAPI WaitForSingleObject(  HANDLE hHandle,  DWORD dwMilliseconds);*/
	uint32_t handle;
	POP_DWORD(c, &handle);
	uint32_t msecs;
	POP_DWORD(c, &msecs);
	uint32_t returnvalue = 0;
	printf("%x\tWaitForSingleObject(h=%x, ms=%x)\n",eip_save, (int)handle, msecs);
	if(opts.interactive_hooks){
		returnvalue = WaitForSingleObject((HANDLE)handle, msecs);	
	}
	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_WriteFile(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);

/*
BOOL WriteFile(
  HANDLE hFile,
  LPCVOID lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
*/
	uint32_t file;
	POP_DWORD(c, &file);

	uint32_t p_buffer;
	POP_DWORD(c,  &p_buffer);

	uint32_t bytestowrite;
	POP_DWORD(c,  &bytestowrite);

	uint32_t max_size = 0x900000;
	if( bytestowrite > max_size ){  //sample 2c2167d371c6e0ccbcee778a4d10b3bd - dzzie 
		printf("\tWriteFile modifying BytesToWrite from %x to %x\n", bytestowrite , max_size);
		bytestowrite = max_size;
	}

	unsigned char *buffer = (unsigned char*)malloc(bytestowrite);
	emu_memory_read_block(mem, p_buffer,(void*) buffer, bytestowrite);

	uint32_t p_byteswritten;
	POP_DWORD(c,  &p_byteswritten);
	
	uint32_t p_overlapped;
	POP_DWORD(c,  &p_overlapped);

	emu_memory_write_dword(emu_memory_get(env->emu), p_byteswritten, bytestowrite);

	if(opts.show_hexdumps && bytestowrite > 0){
		int display_size = bytestowrite;
		if(display_size > 300){
			printf("Showing first 300 bytes...\n");
			display_size = 300;
		}
		hexdump(buffer, display_size);
	}

	uint32_t returnvalue = 1;
	uint32_t written=0;
	if(opts.interactive_hooks == 1 ){
		//technically we should check if overlapped was used...
		returnvalue = WriteFile( (HANDLE)file, buffer, bytestowrite, &written,0);
		if( p_byteswritten != 0) emu_memory_write_dword(mem, p_byteswritten, written);
	}

	printf("%x\tWriteFile(h=%x, buf=%x, len=%x, lpw=%x, lap=%x) = %x\n",eip_save, (int)file, p_buffer, bytestowrite, p_byteswritten,p_overlapped, returnvalue );

	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}














int32_t	__stdcall new_user_hook_VirtualProtect(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
/*
 * BOOL VirtualProtect( 
 *	LPVOID lpAddress, 
 *	DWORD  dwSize, 
 *      DWORD  flNewProtect, 
 *      PDWORD lpflOldProtect 
 *); 
 */
	uint32_t p_address;
	POP_DWORD(c, &p_address);

	uint32_t size;
	POP_DWORD(c, &size);

	uint32_t newprotect;
	POP_DWORD(c, &newprotect);

	uint32_t oldprotect;
	POP_DWORD(c, &oldprotect);

	printf("%x\tVirtualProtect(adr=%x, sz=%x, flags=%x)\n",eip_save, p_address, size ,newprotect);

	set_ret(1);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

//*************************************************************************************
//winsock hooks

int32_t	__stdcall new_user_hook_accept(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);

	uint32_t eip_save;

	POP_DWORD(c, &eip_save);

/*SOCKET accept(
  SOCKET s,
  struct sockaddr* addr,
  int* addrlen
);*/
	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t addr;
	POP_DWORD(c, &addr);
	struct sockaddr sa;
	emu_memory_read_block(mem, addr, &sa, sizeof(struct sockaddr));

	uint32_t addrlen;
	POP_DWORD(c, &addrlen);

	uint32_t returnvalue = 0x68;
	
	printf("%x\taccept(h=%x, sa=%x, len=%x)",eip_save, (int)s, addr, addrlen);

	if(addrlen < sizeof(struct sockaddr)) addrlen = sizeof(struct sockaddr);

	if(opts.interactive_hooks == 1){
		int al = addrlen;
		returnvalue = accept((SOCKET)s, &sa, &al);
		emu_memory_write_dword(mem, addrlen, al);
		emu_memory_write_block(mem, addr, &sa, sizeof(struct sockaddr) );
	}

	printf(" = %x\n", returnvalue);
	if(returnvalue == SOCKET_ERROR) printf("\tlisten failed with error: %ld\n", WSAGetLastError());

	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_bind(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int bind(   SOCKET s,  const struct sockaddr* name,  int namelen); */
	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t p_name;
	POP_DWORD(c, &p_name);
	
	struct sockaddr sa;
	emu_memory_read_block(mem, p_name, &sa, sizeof(struct sockaddr));

	uint32_t namelen;
	POP_DWORD(c, &namelen);
	if (namelen != sizeof(struct sockaddr)) namelen = sizeof(struct sockaddr);

	uint32_t returnvalue = 21 ;
	if(opts.interactive_hooks == 1) returnvalue = bind((SOCKET)s, &sa, namelen);

	printf("%x\tbind(h=%x, port:%d, sz=%x) = %x\n",eip_save, s, get_client_port(&sa),namelen, returnvalue );

	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_closesocket(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{   /*int closesocket(SOCKET s);*/
	uint32_t eip_save;
	uint32_t s;
	uint32_t returnvalue = 0;
	POP_DWORD(cpu, &eip_save);
	POP_DWORD(cpu, &s);
	printf("%x\tclosesocket(h=%x)\n",eip_save, s );
	if(opts.interactive_hooks == 1 ) returnvalue = closesocket((SOCKET)s);
	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_connect(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{	/* int connect(  SOCKET s,  const struct sockaddr* name,  int namelen)*/
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	uint32_t s;
	POP_DWORD(c, &s);
	uint32_t p_name;
	POP_DWORD(c, &p_name);
	struct sockaddr sa;
	emu_memory_read_block(emu_memory_get(env->emu), p_name, &sa, sizeof(struct sockaddr));
	uint32_t namelen;
	POP_DWORD(c, &namelen);
	
	if (opts.override.connect.host != NULL ){
		struct sockaddr_in *si = (struct sockaddr_in *)&sa;
		si->sin_addr.s_addr = inet_addr(opts.override.connect.host);
	}

	if (opts.override.connect.port > 0){
		struct sockaddr_in *si = (struct sockaddr_in *)&sa;;
		si->sin_port = htons(opts.override.connect.port);
	}

	if (namelen != sizeof(struct sockaddr)) namelen = sizeof(struct sockaddr);

	if( opts.interactive_hooks == 0 ){
		set_ret(0x4711);
	}else{
		set_ret( connect((SOCKET)s, &sa, namelen) );
	}

	printf("%x\tconnect(h=%x, host: %s , port: %d ) = %x\n",eip_save, s, get_client_ip(&sa), get_client_port(&sa), cpu->reg[eax]  );

	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_listen(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int listen(   SOCKET s,  int backlog);*/
	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t backlog;
	POP_DWORD(c, &backlog);

	uint32_t returnvalue = 0x21;	
	if(opts.interactive_hooks == 1 ) returnvalue = listen((SOCKET)s, backlog);

	printf("%x\tlisten(h=%x) = %x\n",eip_save,s,returnvalue);

	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_recv(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int recv(  SOCKET s,  char* buf,  int len,  int flags);*/

	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t buf;
	POP_DWORD(c, &buf);

	uint32_t len;
	POP_DWORD(c, &len);

	uint32_t flags;
	POP_DWORD(c, &flags);

	if (len > 4096){
		printf("\tlen being reset to 4096 from %x\n", len);
		len = 4096;
	}

	char *buffer = (char *)malloc(len);
	memset(buffer, 0, len);

	uint32_t returnvalue = 0;
	printf("%x\trecv(h=%x, buf=%x, len=%x, fl=%x)\n", eip_save, s, buf, len, flags);
	
	if(opts.interactive_hooks == 1 ){
		
		returnvalue = recv((SOCKET)s, buffer, len,  flags); //libemu malloced buf

		if(opts.show_hexdumps && returnvalue > 0){
			printf("%d bytes received:\n", returnvalue);
			hexdump((unsigned char*)buf, returnvalue);
		}

		if (returnvalue > 0) emu_memory_write_block(mem, buf, buffer, len);
	}
	
	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_send(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int send(  SOCKET s,  const char* buf,  int len,  int flags);*/
	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t p_buf;
	POP_DWORD(c, &p_buf);

	uint32_t len;
	POP_DWORD(c, &len);

	uint32_t flags;
	POP_DWORD(c, &flags);

	if(len > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		len = MAX_ALLOC; //dzzie
	}

	char *buffer = (char *)malloc(len);
	emu_memory_read_block(mem, p_buf, buffer, len);

	uint32_t returnvalue = len;
	printf("%x\tsend(h=%x, buf=%x, len=%x)\n",eip_save, s, p_buf, len);

	if(opts.show_hexdumps && len > 0 && p_buf > 0)
		hexdump((unsigned char*)buffer,len);
	
	if(opts.interactive_hooks == 1 )
		returnvalue = send((SOCKET)s, buffer, len,  flags);

	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}



int32_t	__stdcall new_user_hook_sendto(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int sendto(  SOCKET s,  const char* buf,  int len,  int flags,  const struct sockaddr* to,  int tolen);*/
	uint32_t s;
	POP_DWORD(c, &s);

	uint32_t p_buf;
	POP_DWORD(c, &p_buf);

	uint32_t len;
	POP_DWORD(c, &len);

	if(len > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		len = MAX_ALLOC; //dzzie
	}
	
	char *buffer = (char *)malloc(len);
	emu_memory_read_block(emu_memory_get(env->emu), p_buf, buffer, len);

	uint32_t flags;
	POP_DWORD(c, &flags);

	uint32_t p_to;
	POP_DWORD(c, &p_to);

	struct sockaddr sa;
	emu_memory_read_block(emu_memory_get(env->emu), p_to, &sa, sizeof(struct sockaddr));

	uint32_t tolen;
	POP_DWORD(c, &tolen);

	uint32_t returnvalue = len;	
	printf("%x\tsendto(h=%x, buf=%x, host: %s, port: %x)\n",eip_save, s, p_buf, get_client_ip(&sa), get_client_port(&sa) );

	if(opts.interactive_hooks ==1) returnvalue = sendto((SOCKET)s,buffer,len,flags,&sa,tolen);

	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}


int32_t	__stdcall new_user_hook_socket(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*SOCKET WSAAPI socket(  int af,  int type,  int protocol);*/
	uint32_t af;
	POP_DWORD(c, &af);

	uint32_t type;
	POP_DWORD(c, &type);

	uint32_t protocol;
	POP_DWORD(c, &protocol);

	uint32_t returnvalue = 65;
	if(opts.interactive_hooks == 1 ){
		returnvalue = (int)socket(af, type, protocol);
	}

	printf("%x\tsocket(%i, %i, %i) = %x\n",eip_save, af, type, protocol, returnvalue);

	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}



int32_t	__stdcall new_user_hook_WSASocketA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
/* SOCKET WSASocket(
  int af,
  int type,
  int protocol,
  LPWSAPROTOCOL_INFO lpProtocolInfo,
  GROUP g,
  DWORD dwFlags
); */
	uint32_t af;
	POP_DWORD(c, &af);

	uint32_t type;
	POP_DWORD(c, &type);

	uint32_t protocol;
	POP_DWORD(c, &protocol);

	uint32_t protocolinfo;
	POP_DWORD(c, &protocolinfo);

	uint32_t group;
	POP_DWORD(c, &group);

	uint32_t flags;
	POP_DWORD(c, &flags);

	uint32_t returnvalue = 66;
	printf("%x\tWSASocket(af=%i, tp=%i, proto=%i, group=%i, flags=%i)\n", eip_save, af, type, protocol,group,flags);

	if(opts.interactive_hooks == 1 ) returnvalue = socket(af, type, protocol);

	set_ret(returnvalue);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}



int32_t	__stdcall new_user_hook_WSAStartup(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	struct emu_cpu *c = emu_cpu_get(env->emu);
	uint32_t eip_save;
	POP_DWORD(c, &eip_save);
	/*int WSAStartup(  WORD wVersionRequested,  LPWSADATA lpWSAData);*/
	uint32_t wsaversionreq;
	POP_DWORD(c, &wsaversionreq);
	uint32_t wsadata;
	POP_DWORD(c, &wsadata);

	printf("%x\tWSAStartup(%x)\n", eip_save, wsaversionreq);

	set_ret(0);
	emu_cpu_eip_set(c, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_CreateFileMappingA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	/*
	HANDLE WINAPI CreateFileMapping(
		  __in      HANDLE hFile,
		  __in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
		  __in      DWORD flProtect,
		  __in      DWORD dwMaximumSizeHigh,
		  __in      DWORD dwMaximumSizeLow,
		  __in_opt  LPCTSTR lpName
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hFile = popd();
	uint32_t lpAttrib = popd();
	uint32_t flProtect = popd();
	uint32_t maxHigh = popd();
	uint32_t maxLow = popd();
	struct emu_string* lpName = popstring();
	uint32_t rv = 0;
	uint32_t org_hFile = hFile;

	//if(opts.interactive_hooks == 1){
		if(maxLow > opts.fopen_fsize) opts.fopen_fsize = maxLow; //reset if max size of file map > file size
		if(hFile < 10){ 
			if(opts.fopen_fpath == NULL){
				printf("\tUse /fopen <file> to do interactive mode for CreateFileMapping\n");
			}else{
				//handle from GetFileSizeScanner...We need a specific type of handle for this though
				hFile = (uint32_t)CreateFile(opts.fopen_fpath, GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); 
				if( hFile == -1 ) hFile = (uint32_t)opts.h_fopen; 
			}
		}
		rv = (uint32_t)CreateFileMapping((HANDLE)hFile, 0,2,0,0,0);
	//}
	
	printf("%x\tCreateFileMappingA(h=%x,%x,%x,%x,%x,lpName=%s) = %x\n", eip_save, org_hFile ,lpAttrib,flProtect,maxHigh,maxLow,emu_string_char(lpName),rv);

	emu_string_free(lpName);
	set_ret(rv);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_WideCharToMultiByte(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	uint32_t a[10] = {0,0,0,0,0,0,0,0,0,0};
	loadargs(8, a);
	/*
		int WideCharToMultiByte(
		  __in   UINT CodePage,
		  __in   DWORD dwFlags,
		  __in   LPCWSTR lpWideCharStr,
		  __in   int cchWideChar,
		  __out  LPSTR lpMultiByteStr,
		  __in   int cbMultiByte,
		  __in   LPCSTR lpDefaultChar,
		  __out  LPBOOL lpUsedDefaultChar
		);
	*/

	uint32_t rv = 0;
	uint32_t bufIn = a[3];
	uint32_t bufInSz = a[4];
	uint32_t bufOut = a[5];
	uint32_t bufOutSz = a[6];

	//we dont feed the shellcode any unicode data from any api hooks, chances they use it native are very low
	//so they are probably trying to convert our api output which is already ansi, so just copy it 
	if(bufInSz < MAX_ALLOC ){
		char* tmp = (char*)malloc(bufInSz);
		emu_memory_read_block(mem,bufIn,tmp,bufInSz);
		emu_memory_write_block(mem, bufOut,tmp,bufOutSz); //if > bufInSz thats their problem emu will allocate
		rv = strlen(tmp);
		free(tmp);
	}
		
	printf("%x\tWideCharToMultiByte(%x,%x,in=%x,sz=%x,out=%x,sz=%x,%x,%x) = %x\n", a[0], a[1] ,a[2],a[3],a[4],a[5],a[6],a[7],a[8],rv);

	set_ret(rv);
	emu_cpu_eip_set(cpu, a[0]);
	return 0;
}

int32_t	__stdcall new_user_hook_GetLogicalDriveStringsA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	uint32_t a[10] = {0,0,0,0,0,0,0,0,0,0};
	loadargs(2, a);
	/*
		DWORD WINAPI GetLogicalDriveStrings(
		  __in   DWORD nBufferLength,
		  __out  LPTSTR lpBuffer
		);
	*/

	uint32_t rv = 0;
	uint32_t bufIn = a[2];
	uint32_t bufInSz = a[1];
	
	//a: c: 613A0063 3A 00 00 00
	if( bufInSz >=8){
		emu_memory_write_dword(mem,bufIn, 0x63003a61);
		emu_memory_write_dword(mem,bufIn+4, 0x0000003a);
		rv = 8;
	}

	printf("%x\tGetLogicalDriveStringsA(sz=%x, buf=%x) = %x\n", a[0], a[1] ,a[2],rv);

	set_ret(rv);
	emu_cpu_eip_set(cpu, a[0]);
	return 0;
}

int32_t	__stdcall new_user_hook_FindWindowA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	/*
		HWND WINAPI FindWindow(
		  __in_opt  LPCTSTR lpClassName,
		  __in_opt  LPCTSTR lpWindowName
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* sClass  = popstring();
	struct emu_string* sWindow = popstring();
	
	printf("%x\tFindWindowA(class=%s, window=%s)\n", eip_save, emu_string_char(sClass), emu_string_char(sWindow) );

	emu_string_free(sClass);
	emu_string_free(sWindow);

	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_DeleteUrlCacheEntryA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOLAPI DeleteUrlCacheEntry(
		  __in  LPCTSTR lpszUrlName
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* sUrl  = popstring();
	
	printf("%x\tDeleteUrlCacheEntryA(%s)\n", eip_save, emu_string_char(sUrl) );

	emu_string_free(sUrl);
	set_ret(1);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_FindFirstFileA(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{
	/*
		HANDLE WINAPI FindFirstFile(
		  __in   LPCTSTR lpFileName,
		  __out  LPWIN32_FIND_DATA lpFindFileData
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* sFile  = popstring();
	uint32_t lpFind = popd();

	uint32_t ret = -1;
	WIN32_FIND_DATA wfd;
	memset(&wfd, 0 , sizeof(WIN32_FIND_DATA));

	printf("%x\tFindFirstFileA(%s, %x)\n", eip_save, emu_string_char(sFile), lpFind );

	if(opts.interactive_hooks == 1 ){
		ret = (uint32_t)FindFirstFile( emu_string_char(sFile), &wfd);
		//todo: copy the strings from our memory file name pointers to the ones in emu memory...
	}

	emu_memory_write_block(mem, lpFind, &wfd, sizeof(WIN32_FIND_DATA) );

	emu_string_free(sFile);
	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall new_user_hook_shdocvw65(struct emu_env *env, struct emu_env_w32_dll_export *ex)
{   //ordial 101 = IEWinMain http://www.kakeeware.com/i_launchie.php
	//since k32 opcodes are from live mem and not static, we dont control compiled in GetCommandLineW string pointer
	//unless we patch it in, which might be a good idea if they use it (see link above)
	uint32_t eip_save = popd();
	struct emu_string* sCmdLine = popstring();
	uint32_t nShowWindow = popd();

	if( sCmdLine->size == 0 )
		printf("%x\tIEWinMain(%x, %x)\n", eip_save, sCmdLine->emu_offset, nShowWindow );
	else
		printf("%x\tIEWinMain(%s, %x)\n", eip_save, emu_string_char(sCmdLine), nShowWindow );

	set_ret(0);

	uint32_t MsgBeepOpcodes;
	emu_memory_read_dword(mem, 0x7e431f7b, &MsgBeepOpcodes);
	if ( MsgBeepOpcodes != 0 ){ //this breaks if we ever add user32 opcodes in.
		//or should i do a MessageBeep hook, and transfer execution to MessageBeep on error if IEWinMain has been called..(messy)
		printf("\tPassing execution to patched MessageBeep()\n");
		emu_cpu_eip_set(cpu, 0x7e431f7b); //messagebeep
	}
	else{ 
		emu_cpu_eip_set(cpu, eip_save);
	}
	
	return 0;
}
