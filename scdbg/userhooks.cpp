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

#pragma warning(disable: 4311)
#pragma warning(disable: 4312)
#pragma warning(disable: 4267)

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <Shlobj.h>
#include <time.h>
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

#include "options.h"
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <winsock.h>
#include <windows.h>
#include <wininet.h>
#include <Shlobj.h>

extern uint32_t FS_SEGMENT_DEFAULT_OFFSET;
extern void hexdump(unsigned char*, int);
extern int file_length(FILE *f);
extern void add_malloc(uint32_t, uint32_t);
extern char* dllFromAddress(uint32_t addr);
extern bool FolderExists(char* folder);
extern struct emu_memory *mem;
extern struct emu_cpu *cpu;    //these two are global in main code
extern bool disable_mm_logging;
extern int fulllookupAddress(int eip, char* buf255);
extern void start_color(enum colors);
extern void end_color(void);
extern char* getDumpPath(char* extension);

enum colors{ mwhite=15, mgreen=10, mred=12, myellow=14, mblue=9, mpurple=5 };

int nextFhandle = 0;
int nextDropIndex=0;
uint32_t MAX_ALLOC  = 0x1000000;
uint32_t next_alloc = 0x00600000; //these increment so we dont walk on old allocs (adjusted up so large allocs dont stomp on stack vars 8.23.12)
uint32_t safe_stringbuf = 0x2531D0; //after the peb just empty space
CONTEXT last_set_context; 
int last_set_context_handle=0;
char *default_host_name = "JOHN_PC1";

char* SafeMalloc(int size){
	char* buf = (char*)malloc(size);
	if( (int)buf == 0){
		printf("Malloc Failed to allocate 0x%x bytes exiting...",size);
		exit(0);
	}
	memset(buf,0,size);
	return buf;
}

int get_fhandle(void){
	nextFhandle+=4;
	return nextFhandle;
}

void pushd(uint32_t arg){														
	uint32_t pushme;									
	bcopy(&arg, &pushme, 4);							
	if (cpu->reg[esp] < 4)								
	{													
		printf("ran out of stack space writing a dword\n");	
		exit(0);										
	}													
	cpu->reg[esp]-=4;									
	emu_memory_write_dword(cpu->mem, cpu->reg[esp], pushme);																			
}

/*these next 2 (maybe 3) seem to be the cleanest way to load args from the stack...*/
uint32_t popd(void){
	uint32_t x=0;
	if( emu_memory_read_dword(cpu->mem, cpu->reg[esp], &x) == -1){
		printf("Failed to read stack memory at 0x%x", cpu->reg[esp]);
		exit(0);
	}
	cpu->reg[esp] += 4; 
	return x;
}

bool isWapi(char*fxName){
	int x = strlen(fxName)-1;
	return fxName[x] == 'W' ? true : false;
}

struct emu_string* popstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_string(mem, addr, str, 1256);
	return str;
}

struct emu_string* popwstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_wide_string(mem, addr, str, 1256);
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

int getFormatParameterCount(emu_string *s){ //test me (unused)...
	
	int sz=0;
	for(int i=0; i < s->size;i++){
		if(s->data[i] == '\0') break; 
		if(s->data[i] == '%' && s->data[i+1] == '%'){
			i++; //skip next as it is escaped shouldnt hit end of string as its not a <= loop and %\0 wouldnt be a legit format string anyway
		}else if(s->data[i] == '%'){	
			sz++;
		}
	}

	return sz;
}

//now by default drops files to the shellcode parent dir unless overridden w -temp
char* SafeTempFile(void){ 
	char  ext[20];
	if(nextDropIndex > 100){
		//printf("To many temp files switching to tempname...\n");
		strncat((char*)ext,tmpnam(NULL),19);
	}else{
		sprintf((char*)ext, "drop_%d", nextDropIndex++);
	}
	return getDumpPath(ext);
}


void set_ret(uint32_t val){ cpu->reg[eax] = val; } 

//by the time our user call is called, the args have already been popped off the stack.
//in r/t that just means that esp has been adjusted and cleaned up for function to 
//return, since there hasnt been any memory writes, we can still grab the return address
//off the stack if we know the arg sizes and calculate it with teh adjustment.
//little bit more work, but safe and doesnt require any otherwise sweeping changes
//to the dll - dzzie
uint32_t get_arg(int arg_adjust){
	uint32_t ret_val = 0;
	emu_memory_read_dword( mem, cpu->reg[esp]+arg_adjust, &ret_val);
	return ret_val; //return the raw value from stack
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

char* getHive(int hive){
	switch((int)hive){
		case 0x80000000: return strdup("HKCR\\");
		case 0x80000001: return strdup("HKCU\\");
		case 0x80000002: return strdup("HKLM\\");
		case 0x80000003: return strdup("HKU\\");
		case 0x80000004: return strdup("HKPD\\");
		case 0x80000005: return strdup("HKPD\\");
		case 0x80000006: return strdup("HKCC\\");
		default:
			char* tmp = (char*)malloc(255);				
			sprintf(tmp, "Unknown hKey: %x", hive);
			return tmp;
	};
}


void GetSHFolderName(int id, char* buf255){
	// Shlobj.h   http://msdn.microsoft.com/en-us/library/bb762494(v=vs.85).aspx

	SHGetSpecialFolderPath(0,buf255,id,FALSE);

/*
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
		case 0x001c: strcpy(buf255, "./LOCAL_APPDATA");break;
		case 0x001d: strcpy(buf255, "./ALTSTARTUP");break;
		case 0x001e: strcpy(buf255, "./COMMON_ALTSTARTUP");break;
		case 0x001f: strcpy(buf255, "./COMMON_FAVORITES");break;
		case 0x0020: strcpy(buf255, "./INTERNET_CACHE");break;
		case 0x0021: strcpy(buf255, "./COOKIES");break;
		case 0x0022: strcpy(buf255, "./HISTORY");break;
		default: sprintf(buf255,"Unknown CSIDL: %x",id);

	}*/

}


void GetAligIDName(int id, char* buf255){
	// Wincrypt.h    http://msdn.microsoft.com/en-us/library/aa375549(v=VS.85).aspx
	switch(id){
			case CALG_3DES:					strcpy(buf255, "CALG_3DES"); break;
			case CALG_3DES_112:				strcpy(buf255, "CALG_3DES_112"); break;
			case CALG_AES:					strcpy(buf255, "CALG_AES"); break;
			case CALG_AES_128:				strcpy(buf255, "CALG_AES_128"); break;
			case CALG_AES_192:				strcpy(buf255, "CALG_AES_192"); break;
			case CALG_AES_256:				strcpy(buf255, "CALG_AES_256"); break;
			case CALG_AGREEDKEY_ANY:		strcpy(buf255, "CALG_AGREEDKEY_ANY"); break;
			case CALG_CYLINK_MEK:			strcpy(buf255, "CALG_CYLINK_MEK"); break;
			case CALG_DES:					strcpy(buf255, "CALG_DES"); break;
			case CALG_DESX:					strcpy(buf255, "CALG_DESX"); break;
			case CALG_DH_EPHEM:				strcpy(buf255, "CALG_DH_EPHEM"); break;
			case CALG_DH_SF:				strcpy(buf255, "CALG_DH_SF"); break;
			case CALG_DSS_SIGN:				strcpy(buf255, "CALG_DSS_SIGN"); break;
			case CALG_ECDH:					strcpy(buf255, "CALG_ECDH"); break;
			case CALG_ECDSA:				strcpy(buf255, "CALG_ECDSA"); break;
			case CALG_ECMQV:				strcpy(buf255, "CALG_ECMQV"); break;
			case CALG_HASH_REPLACE_OWF:      strcpy(buf255, "CALG_HASH_REPLACE_OWF"); break;
			case CALG_HUGHES_MD5:			strcpy(buf255, "CALG_HUGHES_MD5"); break;
			case CALG_HMAC:					strcpy(buf255, "CALG_HMAC"); break;
			case CALG_KEA_KEYX:				strcpy(buf255, "CALG_KEA_KEYX"); break;
			case CALG_MAC:					strcpy(buf255, "CALG_MAC"); break;
			case CALG_MD2:					strcpy(buf255, "CALG_MD2"); break;
			case CALG_MD4:					strcpy(buf255, "CALG_MD4"); break;
			case CALG_MD5:					strcpy(buf255, "CALG_MD5"); break;
			case CALG_NO_SIGN:				strcpy(buf255, "CALG_NO_SIGN"); break;
			case CALG_OID_INFO_CNG_ONLY:      strcpy(buf255, "CALG_OID_INFO_CNG_ONLY"); break;
			case CALG_OID_INFO_PARAMETERS:      strcpy(buf255, "CALG_OID_INFO_PARAMETERS"); break;
			case CALG_PCT1_MASTER:			strcpy(buf255, "CALG_PCT1_MASTER"); break;
			case CALG_RC2:					strcpy(buf255, "CALG_RC2"); break;
			case CALG_RC4:					strcpy(buf255, "CALG_RC4"); break;
			case CALG_RC5:					strcpy(buf255, "CALG_RC5"); break;
			case CALG_RSA_KEYX:				strcpy(buf255, "CALG_RSA_KEYX"); break;
			case CALG_RSA_SIGN:				strcpy(buf255, "CALG_RSA_SIGN"); break;
			case CALG_SCHANNEL_ENC_KEY:     strcpy(buf255, "CALG_SCHANNEL_ENC_KEY"); break;
			case CALG_SCHANNEL_MAC_KEY:     strcpy(buf255, "CALG_SCHANNEL_MAC_KEY"); break;
			case CALG_SCHANNEL_MASTER_HASH: strcpy(buf255, "CALG_SCHANNEL_MASTER_HASH"); break;
			case CALG_SEAL:					strcpy(buf255, "CALG_SEAL"); break;
			case CALG_SHA:					strcpy(buf255, "CALG_SHA"); break;
			//case CALG_SHA1:					strcpy(buf255, "CALG_SHA1"); break;
			case CALG_SHA_256:				strcpy(buf255, "CALG_SHA_256"); break;
			case CALG_SHA_384:				strcpy(buf255, "CALG_SHA_384"); break;
			case CALG_SHA_512:				strcpy(buf255, "CALG_SHA_512"); break;
			case CALG_SKIPJACK:				strcpy(buf255, "CALG_SKIPJACK"); break;
			case CALG_SSL2_MASTER:			strcpy(buf255, "CALG_SSL2_MASTER"); break;
			case CALG_SSL3_MASTER:			strcpy(buf255, "CALG_SSL3_MASTER"); break;
			case CALG_SSL3_SHAMD5:			strcpy(buf255, "CALG_SSL3_SHAMD5"); break;
			case CALG_TEK:					strcpy(buf255, "CALG_TEK"); break;
			case CALG_TLS1_MASTER:			strcpy(buf255, "CALG_TLS1_MASTER"); break;
			case CALG_TLS1PRF:				strcpy(buf255, "CALG_TLS1PRF"); break;
			default:						sprintf(buf255,"Unknown ALGID: %x",id);
			}
}

char* processNameForPid(uint32_t pid){
	
	uint32_t pids[10] = {0,400,788,852,880,924,936,1744,2116,9108};
	char* names[10] = {"","iexplorer.exe","smss.exe","csrss.exe","winlogon.exe","services.exe","lsass.exe","svchost.exe","explorer.exe","firefox.exe"};

	for(int i=0;i<10;i++){
		if(pid == pids[i]) return strdup(names[i]);
	}

	return strdup("");
}

int32_t	__stdcall hook_GetModuleHandleA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   //HMODULE WINAPI GetModuleHandle( __in_opt  LPCTSTR lpModuleName);
	uint32_t eip_save = popd();
	struct emu_string *s_filename = popstring();
	char *dllname = emu_string_char(s_filename);

	int i=0;
	int found_dll = 0;
	cpu->reg[eax] = 0; //default = fail

	for (i=0; win->loaded_dlls[i] != NULL; i++)
	{
		if (stricmp(win->loaded_dlls[i]->dllname, dllname) == 0)
		{
			cpu->reg[eax]= win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
			break;
		}
	}
	 
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(win, dllname) == 0)
        {
            cpu->reg[eax] = win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
        }
	}

	printf("%x\tGetModuleHandleA(%s)\n",eip_save,  dllname);
	if (found_dll == 0) printf("\tUnknown Dll - Not implemented by libemu\n");

	emu_string_free(s_filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_MessageBoxA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_ShellExecuteA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	uint32_t eip_save = popd();
	uint32_t hwnd = popd();
	uint32_t lpOperation = popd();
	struct emu_string  *sFile = popstring();
	struct emu_string  *sParam = popstring();
	uint32_t lpDirectory = popd();
	uint32_t nShowCmd = popd();

	printf("%x\tShellExecuteA(%s, %s)\n",eip_save,  sFile->data, sParam->data);
	
	emu_string_free(sFile);
	emu_string_free(sParam);

	cpu->reg[eax] = 33;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SHGetSpecialFolderPathA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
CopyBOOL SHGetSpecialFolderPath(
         HWND hwndOwner,
  __out  LPTSTR lpszPath,
  __in   int csidl,
  __in   BOOL fCreate
);

*/
	uint32_t eip_save = popd();
	uint32_t hwnd = popd();
	uint32_t buf = popd();
	uint32_t csidl = popd();
	uint32_t fCreate = popd();

	char buf255[255];
	memset(buf255,0,254);
	GetSHFolderName(csidl, (char*)&buf255);

	printf("%x\tSHGetSpecialFolderPathA(buf=%x, %s)\n",eip_save, buf, buf255 );
	
	emu_memory_write_block(mem,buf,buf255,strlen(buf255));

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SHGetFolderPathA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
HRESULT SHGetFolderPath(
  __in   HWND hwndOwner,
  __in   int nFolder,
  __in   HANDLE hToken,
  __in   DWORD dwFlags,
  __out  LPTSTR pszPath
);
*/
	uint32_t eip_save = popd();
	uint32_t hwnd = popd();
	uint32_t csidl = popd();
	uint32_t hToken = popd();
	uint32_t flags = popd();
	uint32_t buf = popd();

	char buf255[255];
	memset(buf255,0,254);
	GetSHFolderName(csidl, (char*)&buf255);

	printf("%x\tSHGetFolderPathA(buf=%x, %s)\n",eip_save, buf, buf255 );
	
	emu_memory_write_block(mem,buf,buf255,strlen(buf255));

	cpu->reg[eax] = 0;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GenericStub(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{

	uint32_t eip_save = popd();
/*
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
  BOOL InternetCloseHandle( __in  HINTERNET hInternet );
  HANDLE WINAPI GetCurrentThread(void);
  bool CloseServiceHandle(HANDLE)

  BOOL WINAPI AdjustTokenPrivileges(
  _In_       HANDLE TokenHandle,
  _In_       BOOL DisableAllPrivileges,
  _In_opt_   PTOKEN_PRIVILEGES NewState,
  _In_       DWORD BufferLength,
  _Out_opt_  PTOKEN_PRIVILEGES PreviousState,
  _Out_opt_  PDWORD ReturnLength
);


*/
	int dwCreationFlags=0;

	int arg_count = -1 ;
	int ret_val   =  1 ;
    int log_val   = -1 ; //stub support optional logging of two int arg
	int log_val2  = -1 ; 

	char* func = ex->fnname;

	if(strcmp(func, "GetCurrentProcess") ==0 )     arg_count = 0;
	if(strcmp(func, "GetCurrentThread") ==0 )      arg_count = 0;
	if(strcmp(func, "RevertToSelf") ==0 )          arg_count = 0;
	if(strcmp(func, "CloseServiceHandle") ==0 )    arg_count = 1;
	if(strcmp(func, "DeleteService") ==0 )         arg_count = 1;
	if(strcmp(func, "RtlDestroywinironment") ==0 ) arg_count = 1;
	if(strcmp(func, "FindClose") == 0 )    	       arg_count = 1;
	if(strcmp(func, "SetSystemTime") ==0 ) 		   arg_count = 1;
	if(strcmp(func, "AdjustTokenPrivileges") ==0 ) arg_count = 6;
	
	if(strcmp(func, "InternetCloseHandle") ==0 ){
		arg_count = 1;
		log_val = get_arg(0);
	}

	if(strcmp(func, "FlushViewOfFile") ==0 ){
		arg_count = 2;
		log_val = get_arg(0);  //base address
		log_val2 = get_arg(4);  //size
	}

	if(strcmp(func, "UnmapViewOfFile") ==0 ){
		arg_count = 1;
		log_val = get_arg(0);  //base address
	}
	

	if(strcmp(func, "GetSystemTime") ==0 ){
		arg_count = 1;
		log_val = get_arg(0);  //lpSystime
		SYSTEMTIME st;
		GetSystemTime(&st);
		emu_memory_write_block( mem, log_val, &st, sizeof(SYSTEMTIME));
	}
 
	if(strcmp(func, "FreeLibrary") ==0 ){
		log_val = get_arg(0);  //hmodule
		arg_count = 1;
	}

	if(strcmp(func, "CreateThread") ==0 ){
		log_val = get_arg(8);  //start address
		log_val2 = get_arg(12);  //parameter
		dwCreationFlags = get_arg(16);
		//todo handle optional threadID parameter in case of resume thread...(make this its own stub)
		arg_count = 6;
	}

	if(strcmp(func, "GlobalFree") ==0 ){
		log_val = get_arg(0);  //hmem
		ret_val = 0;
		arg_count = 1;
	}

	if(strcmp(func, "RtlExitUserThread") ==0 ){
		arg_count = 1;
		log_val = get_arg(0); //handle
		opts.steps =0;
	}

	if(strcmp(func, "ZwTerminateProcess") == 0 
		|| strcmp(func, "ZwTerminateThread") == 0
		|| strcmp(func, "TerminateThread") == 0
		|| strcmp(func, "TerminateProcess") == 0
	){
		log_val = get_arg(0); //handle
		arg_count = 2;
		opts.steps =0;
	}

	if(arg_count == -1 ){
		printf("invalid use of generic stub no match found for %s",func);
		exit(0);
	}

	int r_esp = cpu->reg[esp];
	r_esp += arg_count*4;
	
	cpu->reg[esp] = r_esp;

	bool nolog = false;

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
		pushd(log_val2);
		pushd(eip_save);
		emu_cpu_eip_set(cpu, log_val);
		printf("\tTransferring execution to threadstart...\n");
	}else{
		cpu->reg[eax] = ret_val;
		emu_cpu_eip_set(cpu, eip_save);
	}
	
	return 0;

}


int32_t	__stdcall hook_CreateProcessInternal(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
/*
	DWORD WINAPI CreateProcessInternal(  
		__in         DWORD unknown1,                              // always (?) NULL  
		__in_opt     LPCTSTR lpApplicationName,  
		__inout_opt  LPTSTR lpCommandLine,  
		__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,  
		__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,  
		__in         BOOL bInheritHandles,  
		__in         DWORD dwCreationFlags,  
		__in_opt     LPVOID lpwinironment,  
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
	emu_cpu_eip_set(cpu, eip_save);
	return 1;
}


int32_t	__stdcall hook_GlobalAlloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	CopyHGLOBAL WINAPI GlobalAlloc(
	  __in  UINT uFlags,
	  __in  SIZE_T dwBytes
	);
	HLOCAL WINAPI LocalAlloc(
	  __in  UINT uFlags,
	  __in  SIZE_T uBytes
	);
*/
	uint32_t eip_save = popd();
	uint32_t flags = popd();
	uint32_t size = popd();

	uint32_t baseMemAddress = next_alloc;

	if(size > 0 && size < MAX_ALLOC){
		set_next_alloc(size);
		void *buf = malloc(size);
		memset(buf,0,size);
		emu_memory_write_block(mem,baseMemAddress,buf, size);
		printf("%x\t%s(sz=%x) = %x\n", eip_save, ex->fnname, size, baseMemAddress);
		free(buf);
	}else{
		printf("%x\t%s(sz=%x) (Ignored size out of range)\n", eip_save, ex->fnname, size);
	}

	cpu->reg[eax] = baseMemAddress;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_MapViewOfFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_URLDownloadToCacheFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
/*
	HRESULT URLDownloadToCacheFile(      
		LPUNKNOWN lpUnkcaller,
		LPCSTR szURL,
  [out] LPTSTR szFileName,
		DWORD cchFileName,
		DWORD dwReserved,
		IBindStatusCallback *pBSC
	);
*/
	uint32_t eip_save  = popd();
	uint32_t lpUnk     = popd();
	struct emu_string *sUrl = popstring();
	uint32_t p_fname   = popd();
	uint32_t bufsz     = popd();
	uint32_t reserved  = popd();
	uint32_t callback  = popd();

	//unicode version now redirected here too..
	printf("%x\t%s(%s, buf=%x)\n",eip_save, ex->fnname , sUrl->data, p_fname);

	char* tmp = "c:\\URLCacheTmpPath.exe";
	uint32_t leng = strlen(tmp);
	if( bufsz < leng ) leng = bufsz;

	if(leng > 0 ){
		emu_memory_write_block(mem,p_fname, tmp, leng);
		emu_memory_write_byte(mem,p_fname + leng+1, 0x00);
	}

	emu_string_free(sUrl);
	cpu->reg[eax] = 0; // S_OK 
	emu_cpu_eip_set(cpu, eip_save);
	return 1;
}

int32_t	__stdcall hook_system(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
	struct emu_string *cmd = popstring();
	printf("%x\tsystem(%s)\n",eip_save,  cmd->data);
	emu_string_free(cmd);
	cpu->reg[eax] =  0;  
	emu_cpu_eip_set(cpu, eip_save);
	return 1;
}

int32_t	__stdcall hook_VirtualAlloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	LPVOID WINAPI VirtualAlloc(
	  __in_opt  LPVOID lpAddress,
	  __in      SIZE_T dwSize,
	  __in      DWORD flAllocationType,
	  __in      DWORD flProtect
);
*/
	uint32_t eip_save = popd();
	uint32_t address = popd();
	uint32_t size = popd();
	uint32_t atype = popd();
	uint32_t flProtect = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_VirtualProtectEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	BOOL WINAPI VirtualProtectEx(
	  __in   HANDLE hProcess,
	  __in   LPVOID lpAddress,
	  __in   SIZE_T dwSize,
	  __in   DWORD flNewProtect,
	  __out  PDWORD lpflOldProtect
	);
*/
	uint32_t eip_save = popd();
	uint32_t hProcess = popd();
	uint32_t address = popd();
	uint32_t size = popd();
	uint32_t flNewProtect = popd();
	uint32_t lpflOldProtect = popd();

	printf("%x\tVirtualProtectEx(hProc=%x, addr=%x , sz=%x, prot=%x)\n", eip_save, hProcess, address, size, flNewProtect);
		
	cpu->reg[eax] = 1;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}



//need to find a clean way to have these stubs handle multiple api..this is a start anyway..
//this one can handle logging of 1 or 2 string args..
int32_t	__stdcall hook_GenericStub2String(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save  = popd();
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
		log_sarg = get_arg(0);  //lpszAgent
		arg_count = 5;
	}

	if(strcmp(func, "InternetOpenUrlA") ==0 ){
		//printf("InternetOpenUrlA\n");
		log_sarg = get_arg(4);  //url
		sarg1_len = 500;
		arg_count = 6;
	}

	if(strcmp(func, "SHRegGetBoolUSValueA") ==0 ){
		log_sarg = get_arg(0);  //pszSubKey
		log_sarg2 = get_arg(4);  //pszValue
		arg_count = 4;
		ret_val = 0;
	}

	if(arg_count==0){
		printf("invalid use of generic stub 2 string no match found for %s",func);
		exit(0);
	}

	int r_esp = cpu->reg[esp];
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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_SetFilePointer(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
/*
	
	DWORD WINAPI SetFilePointer(
  __in         HANDLE hFile,
  __in         LONG lDistanceToMove,
  __inout_opt  PLONG lpDistanceToMoveHigh,
  __in         DWORD dwMoveMethod
);


*/
	uint32_t eip_save = popd();
	uint32_t hfile = popd();
	uint32_t lDistanceToMove = popd();
	uint32_t lDistanceToMoveHigh = popd();
	uint32_t dwMoveMethod = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ReadFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*	
	BOOL WINAPI ReadFile(
	  __in         HANDLE hFile,
	  __out        LPVOID lpBuffer,
	  __in         DWORD nNumberOfBytesToRead,
	  __out_opt    LPDWORD lpNumberOfBytesRead,
	  __inout_opt  LPOVERLAPPED lpOverlapped
	);
*/
	uint32_t eip_save = popd();
	uint32_t hfile = popd();
	uint32_t lpBuffer = popd();
	uint32_t numBytes = popd();
	uint32_t lpNumBytes = popd();
	uint32_t lpOverlap = popd();
	
	//numBytes++;
	uint32_t m_hfile = hfile;
	uint32_t bytesRead=0;
	BOOL rv = FALSE;

	if( opts.interactive_hooks == 1){
		if( (int)opts.h_fopen != 0 && hfile  < 10 ) m_hfile = (uint32_t)opts.h_fopen; //scanners start at 1 or 4 we let them go with it..
		char* tmp = (char*)malloc(numBytes);
		if(tmp==0){
			printf("\tFailed to allocate %x bytes skipping ReadFile\n",numBytes);
		}else{
			rv = ReadFile( (HANDLE)m_hfile, tmp, numBytes, &bytesRead, 0);
			emu_memory_write_block(mem, lpBuffer,tmp, numBytes);
			if( bytesRead != numBytes && !opts.norw) printf("\tReadFile error? numBytes=%x bytesRead=%x rv=%x\n", numBytes, bytesRead, rv);
			free(tmp);
		}
	}

	bool isSpam = strcmp(win->lastApiCalled, "ReadFile") == 0 ? true : false;

	if(!isSpam && !opts.norw)
		printf("%x\tReadFile(hFile=%x, buf=%x, numBytes=%x) = %x\n", eip_save, hfile, lpBuffer, numBytes, rv);
	
	if(isSpam && win->lastApiHitCount == 2) printf("\tHiding repetitive ReadFile calls\n");

	if(lpNumBytes != 0) emu_memory_write_dword(mem, lpNumBytes, numBytes);

	cpu->reg[eax] = 1;
	emu_cpu_eip_set(cpu, eip_save);
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


int32_t	__stdcall hook_strstr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* char *strstr(const char *s1, const char *s2); */
	uint32_t eip_save  = popd();
	uint32_t s1 = popd();
	uint32_t s2 = popd();
	uint32_t ret=0;
	
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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_strtoul(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*	
	unsigned long strtoul(const char *restrict str, char **restrict endptr, int base);
*/
	uint32_t eip_save = popd();
	uint32_t s1 = popd();
	uint32_t s2 = popd();
	uint32_t base = popd();

	uint32_t ret=0;
	
	struct emu_string *arg = emu_string_new();
	uint32_t len = emu_string_length(s1, 0x6000);
	emu_memory_read_string(mem, s1, arg, len);
	ret = strtoul( emu_string_char(arg), NULL, base);

	printf("%x\tstrtoul(buf=%x -> \"%s\", base=%d) = %x\n", eip_save, s1, emu_string_char(arg), base, ret);
	
	emu_string_free(arg);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetTempFileName(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*	
	UINT WINAPI GetTempFileName(
	  __in   LPCTSTR lpPathName,
	  __in   LPCTSTR lpPrefixString,
	  __in   UINT uUnique,
	  __out  LPTSTR lpTempFileName
	);
*/
	uint32_t eip_save = popd();
	struct emu_string* lpPathName = isWapi(ex->fnname) ? popwstring() : popstring();
	struct emu_string* lpPrefixString = isWapi(ex->fnname) ? popwstring() : popstring();
	uint32_t unique = popd();
	uint32_t out_buf = popd();

	char* realBuf = (char*)malloc(256);
	uint32_t ret = GetTempFileName(lpPathName->data, lpPrefixString->data, unique, realBuf); 
	
	printf("%x\t%s(path=%s, prefix=%x, unique=%x, buf=%x) = %X\n", eip_save, ex->fnname, 
			 lpPathName->data, lpPrefixString->emu_offset, unique, out_buf, ret);

	if(ret!=0){
		printf("\t Path = %s\n", realBuf);
		emu_memory_write_block(mem, out_buf, realBuf, strlen(realBuf)+1);
	}

	if( isWapi(ex->fnname) ){
		emu_memory_write_word(mem, out_buf+strlen(realBuf), 0);
	}
	
	free(realBuf);
	emu_string_free(lpPathName);
	emu_string_free(lpPrefixString);

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_LoadLibrary(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
   LoadLibraryA(LPCTSTR lpFileName); 
   LoadLibraryExA(LPCTSTR lpFileName, hFile, flags)
*/
	uint32_t eip_save = popd();
	//struct emu_string *dllstr = popstring();
	struct emu_string *dllstr = isWapi(ex->fnname) ? popwstring() :  popstring();

	int i=0;
	int found_dll = 0;
	uint32_t dummy;

	char* func = ex->fnname;
    	
	if(strcmp(func, "LoadLibraryExA") ==0 ){
		dummy = popd();
		dummy = popd();
	}

	char *dllname = dllstr->data;

	for (i=0; win->loaded_dlls[i] != NULL; i++)
	{
		if (stricmp(win->loaded_dlls[i]->dllname, dllname) == 0)
		{
			cpu->reg[eax] = win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
			break;
		}
	}
	
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(win, dllname) == 0)
        {
            cpu->reg[eax] = win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
        }
        else
        {
            cpu->reg[eax] = 0;
        }
	}

	printf("%x\t%s(%s)\n",eip_save, func, dllname);
	if(found_dll == 0) printf("\tUnknown Dll - Not implemented by libemu\n");

	emu_string_free(dllstr);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetModuleFileName(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	DWORD WINAPI GetModuleFileName(
	  __in_opt  HMODULE hModule,
	  __out     LPTSTR lpFilename,
	  __in      DWORD nSize
	);
*/
	uint32_t eip_save = popd();
	uint32_t hmod = popd();
	uint32_t lpfname = popd();
	uint32_t nsize = popd();

	int i=0;
	char ret[255]={0} ;

	if(hmod==0){
		strcpy(ret,"c:\\Program Files\\scdbg\\parentApp.exe");
	}else{
		for (i=0; win->loaded_dlls[i] != NULL; i++){
			if (win->loaded_dlls[i]->baseaddr == hmod){
				sprintf(ret, "c:\\Windows\\System32\\%s", win->loaded_dlls[i]->dllname);
				break;
			}
		}
	}

	i = strlen(ret);

	printf("%x\t%s(hmod=%x, buf=%x, sz=%x) = %s\n",eip_save, ex->fnname,  hmod, lpfname, nsize, ret);

	if(i > 0 && i < nsize){
		emu_memory_write_block(mem, lpfname, &ret, i);
	} 

	cpu->reg[eax] =  i;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_DialogBoxIndirectParamA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	INT_PTR WINAPI DialogBoxIndirectParam(
	  __in_opt  HINSTANCE hInstance,
	  __in      LPCDLGTEMPLATE hDialogTemplate,
	  __in_opt  HWND hWndParent,
	  __in_opt  DLGPROC lpDialogFunc,
	  __in      LPARAM dwInitParam
	);
*/
	uint32_t eip_save = popd();
	uint32_t hmod = popd();
	uint32_t hdlg = popd();
	uint32_t hwnd = popd();
	uint32_t lpproc = popd();
	uint32_t param = popd();

	printf("%x\tDialogBoxIndirectParamA(hmod=%x, hdlg=%x, hwnd=%x, proc=%x, param=%x)\n",
		eip_save, hmod, hdlg, hwnd, lpproc, param);

	cpu->reg[eax] = 1;

	if( lpproc != 0 ){
		pushd(param);
		pushd(eip_save);
		emu_cpu_eip_set(cpu, lpproc);
		printf("\tTransferring execution to DialogProc...\n");
	}else{
		emu_cpu_eip_set(cpu, eip_save);
	}

	return 0;
}

int32_t	__stdcall hook_ZwQueryVirtualMemory(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	
	uint32_t eip_save = popd();
	uint32_t hproc = popd();
	uint32_t base = popd();
	uint32_t mem_info_class = popd();
	uint32_t mem_info = popd();
	uint32_t mem_info_len = popd();
	uint32_t ret_len = popd();
	
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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

/*int32_t	__stdcall hook_GetEnvironmentVariableA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
/*
	DWORD WINAPI GetEnvironmentVariableA(
	  __in_opt   LPCTSTR lpName,
	  __out_opt  LPTSTR lpBuffer,
	  __in       DWORD nSize
	);	
* /
	uint32_t eip_save = popd();
	struct emu_string *var_name = popstring();
	uint32_t buf = popd();
	uint32_t size = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}*/

int32_t	__stdcall hook_VirtualAllocEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	LPVOID WINAPI VirtualAllocEx(
	  __in      HANDLE hProcess,
	  __in_opt  LPVOID lpAddress,
	  __in      SIZE_T dwSize,
	  __in      DWORD flAllocationType,
	  __in      DWORD flProtect
);
*/
	uint32_t eip_save = popd();
	uint32_t hproc = popd();
	uint32_t address = popd();
	uint32_t size = popd();
	uint32_t atype = popd();
	uint32_t flProtect = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_WriteProcessMemory(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{

/*
	BOOL WINAPI WriteProcessMemory( //we assume its a process injection with base=VirtuaAllocEx so we embed there
	  __in   HANDLE hProcess,
	  __in   LPVOID lpBaseAddress,
	  __in   LPCVOID lpBuffer,
	  __in   SIZE_T nSize,
	  __out  SIZE_T *lpNumberOfBytesWritten
	);
*/
	uint32_t eip_save = popd();
	uint32_t hproc = popd();
	uint32_t address = popd();
	uint32_t buf = popd();
	uint32_t size = popd();
	uint32_t BytesWritten = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_CreateRemoteThread(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	uint32_t eip_save = popd();
	uint32_t hproc   = popd();
	uint32_t attributes = popd();
	uint32_t stackSize  = popd();
	uint32_t address = popd();
	uint32_t arg     = popd();
	uint32_t flags   = popd();
	uint32_t id      = popd();

	printf("%x\tCreateRemoteThread(pid=%x, addr=%x , arg=%x, flags=%x, *id=%x)\n", eip_save, hproc, address, arg, flags, id);

	if((flags == 0 || flags == 0x10000) ){ /* actually should check specific bitflags */
		pushd(arg);
		pushd(eip_save);
		emu_cpu_eip_set(cpu, address);
		printf("\tTransferring execution to threadstart...\n");
	}else{
		cpu->reg[eax] = 0x222;
		emu_cpu_eip_set(cpu, eip_save);
	}

	return 0;
}


int32_t	__stdcall hook_MultiByteToWideChar(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	uint32_t eip_save = popd();
	uint32_t cp      = popd();
	uint32_t flags   = popd();
	struct emu_string *s_src = popstring();
	uint32_t size    = popd();
	uint32_t dst     = popd();
	uint32_t dstsz   = popd();

	if(opts.verbose > 0){
		printf("%x\tMultiByteToWideChar(cp=%x, fl=%x , src=%x, sz=%x, dst=%x, dstsz=%x)\n", eip_save, cp, flags, s_src->emu_offset, size, dst,dstsz);
		printf("\t%x -> %s\n", s_src->emu_offset, s_src->data);
	}else{
		printf("%x\tMultiByteToWideChar(%s)\n", eip_save, s_src->data);
	}

	int retval = ( s_src->size * 2);

	if(dst != 0 && dstsz!=0 && dstsz < MAX_ALLOC && dstsz >= retval){ 
		//just write the ascii string to the unicode buf, they are probably just gonna 
		//pass it back to our hook. work an experiment to see if it causes problems or not
		emu_memory_write_block(mem, dst, s_src->data, s_src->size);
		emu_memory_write_word(mem,dst+s_src->size+1,0);
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
		
	emu_string_free(s_src);
	cpu->reg[eax] = retval;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_URLDownloadToFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
/*
HRESULT URLDownloadToFile(
  LPUNKNOWN pCaller,
  LPCTSTR szURL,
  LPCTSTR szFileName,
  DWORD dwReserved,
  LPBINDSTATUSCALLBACK lpfnCB
);
*/
	uint32_t eip_save = popd();
	uint32_t p_caller = popd();
	struct emu_string *url = isWapi(ex->fnname) ? popwstring() : popstring();
	struct emu_string *filename = isWapi(ex->fnname) ? popwstring() : popstring();
	uint32_t reserved = popd();
	uint32_t statuscallbackfn = popd();

	printf("%x\t%s(%s, %s)\n",eip_save, ex->fnname, url->data , filename->data);

	cpu->reg[eax] = 0;
	emu_string_free(url);
	emu_string_free(filename);
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook__execv(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
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
	uint32_t eip_save = popd();
	struct emu_string *cmdname = popstring();
	uint32_t p_argv = popd();

	printf("%x\t_execv(%s, %x)\n", eip_save, cmdname->data, p_argv);

	set_ret(0x1988);
	emu_string_free(cmdname);
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_fclose(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	cdecl int fclose( FILE *stream ); */
	uint32_t eip_save = popd();
	uint32_t p_stream = get_arg(0);

	printf("%x\tfclose(h=%x)\n",eip_save, (int)p_stream);

	if( opts.interactive_hooks == 0 ){
		cpu->reg[eax] = 0x4711;
	}else{
    	cpu->reg[eax] = fclose((FILE*)p_stream);
	}
	
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_fseek(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	cdecl int fseek ( FILE * stream, long int offset, int origin ); */
	uint32_t eip_save = popd();
	uint32_t h = get_arg(0);
	uint32_t off = get_arg(4);
	uint32_t org = get_arg(8);

	printf("%x\tfseek(h=%x, off=%x, org=%x)\n",eip_save, h, off, org);
	
	uint32_t ret = 0;
	if( opts.interactive_hooks != 0 ){
		ret = fseek((FILE*)h,off,org);
	}
	
	set_ret(ret);
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_fprintf(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	cdecl int fprintf ( FILE * stream, const char * format, ... ); */
	uint32_t eip_save = popd();
	uint32_t stream = get_arg(0);
	uint32_t p_fmat = get_arg(4);
	
	struct emu_string *fmat = emu_string_new();
	emu_memory_read_string(mem, p_fmat, fmat, 1256);

	/*int sz = getFormatParameterCount(fmat); //cdecl unneeded...
	while(sz--){
		popd();
	}*/

	printf("%x\tfprintf(h=%x, %s)\n",eip_save, stream, fmat->data);

	set_ret(fmat->size); 
    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(fmat);
	return 0;
}

int32_t	__stdcall hook_fopen(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		cdecl FILE *fopen( const char *filename, const char *mode );
		cdecl FILE *_wfopen( const wchar_t *filename, const wchar_t *mode );
	*/
	uint32_t eip_save = popd();
	uint32_t p_filename = get_arg(0);
	uint32_t p_mode = get_arg(4);

	struct emu_string *filename = emu_string_new();
	emu_memory_read_string(cpu->mem, p_filename, filename, 512);
	
	struct emu_string *mode = emu_string_new();
	emu_memory_read_string(mem, p_mode, mode, 512);
	
	if( opts.interactive_hooks == 0){
		printf("%x\tfopen(%s, %s) = %x\n", eip_save, emu_string_char(filename), emu_string_char(mode), 0x4711);
		cpu->reg[eax] = 0x4711;
	}else{
		char* localfile = SafeTempFile();
		FILE *f = fopen(localfile,"w");
		printf("%x\tfopen(%s) = %x\n", eip_save, filename, (int)f);
		start_color(myellow);
		printf("\tInteractive mode local file: %s\n", localfile);
		end_color();
		free(localfile);
		cpu->reg[eax] = (int)f; 
	}

	emu_string_free(filename);
	emu_string_free(mode);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_fwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*  cdecl size_t fwrite( const void *buffer, size_t size, size_t count, FILE *stream );  */
	uint32_t eip_save = popd();
	uint32_t p_buffer = get_arg(0);
	uint32_t size = get_arg(4);
	uint32_t count = get_arg(8);
	uint32_t p_stream = get_arg(12);
	
	uint32_t len = size * count;

	uint32_t MAX_ALLOC = 0x900000;
	if(len > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		len = MAX_ALLOC; //dzzie
	}

	unsigned char *buffer = (unsigned char*)malloc(len);
	emu_memory_read_block(mem, p_buffer, buffer, len);
		
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
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook__lcreat(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	LONG _lcreat(
	  LPCSTR lpszFileName,
	  int fnAttribute
	);
*/	
	uint32_t eip_save = popd();
	struct emu_string *filename = popstring();
	uint32_t fnAttribute = popd();

	printf("%x\t_lcreate(%s)\n",eip_save, filename->data);
	
	uint32_t handle = 0;

	if(opts.interactive_hooks != 0){
		char *localfile = SafeTempFile();
		FILE *f = fopen(localfile,"w");
		start_color(myellow);
		printf("\tInteractive mode local file: %s\n", localfile);
		end_color();
		free(localfile);
		handle = (int)f;
	}else{
		handle = get_fhandle();
	}

	cpu->reg[eax] = handle;
	emu_string_free(filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook__lclose(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* HFILE _lclose( HFILE hFile	); */
	uint32_t eip_save = popd();
	uint32_t file = popd();

	printf("%x\t_lclose(h=%x)\n",eip_save,file);

	cpu->reg[eax] = 0;
	if( opts.interactive_hooks != 0 ) cpu->reg[eax] = fclose((FILE*)file);

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook__lwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	LONG _lwrite(
	  HFile hFile,
	  LPCSTR lpBuffer,
	  UINT cbWrite
	);
*/
	uint32_t eip_save = popd();
	uint32_t file = popd();
	uint32_t p_buffer = popd();
	uint32_t size = popd();

	uint32_t MAX_ALLOC = 0x900000;
	if(size > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		size = MAX_ALLOC; //dzzie
	}

	unsigned char *buffer = (unsigned char*)malloc(size);
	emu_memory_read_block(mem, p_buffer, buffer, size);
	
	printf("%x\t_lwrite(h=%x, buf=%x)\n",eip_save, file, p_buffer);

	if(opts.show_hexdumps && buffer != 0 && size > 0) hexdump((unsigned char*)buffer, size);

	cpu->reg[eax] = size;

	if(opts.interactive_hooks != 0 ){
		int r = fwrite((void*)buffer, 1, size, (FILE*)file);
		set_ret(r);
	}

	free(buffer);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetTempPath(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
	DWORD WINAPI GetTempPath(
	  __in   DWORD nBufferLength,
	  __out  LPTSTR lpBuffer
	);
	*/
	uint32_t eip_save = popd();
	uint32_t bufferlength = popd();
	uint32_t p_buffer = popd();

	char* realBuf = (char*)malloc(256);
	uint32_t ret = GetTempPath(256,realBuf);
	
	if( (ret+1) > bufferlength) ret = 0;
	if(ret!=0) emu_memory_write_block(mem, p_buffer, realBuf, ret+1);
	
	if( isWapi(ex->fnname) ){ //kind of a hack since we dont really return unicode data still must terminate as if..
		emu_memory_write_byte(mem,p_buffer+ret+1, 0);
		ret+=2;
	}

	printf("%x\t%s(len=%x, buf=%x) = %x\n",eip_save, ex->fnname, bufferlength, p_buffer, ret);
	
	free(realBuf);
	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetTickCount(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
	uint32_t tickcount = rand();
	set_ret(tickcount);
	printf("%x\tGetTickCount() = %x\n", eip_save, tickcount);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook__hwrite(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	return hook__lwrite(win, ex);
}

int32_t	__stdcall hook_WinExec(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* UINT WINAPI WinExec( LPCSTR lpCmdLine, UINT uCmdShow);*/
	uint32_t eip_save = popd();
	struct emu_string *cmdstr = popstring();
	uint32_t show = popd();
	 
	printf("%x\tWinExec(%s)\n",eip_save, cmdstr->data);

	emu_string_free(cmdstr);
	set_ret(32);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_Sleep(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
	uint32_t dwMilliseconds = popd();
	set_ret(0);
	printf("%x\tSleep(0x%x)\n", eip_save, dwMilliseconds);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_DeleteFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	uint32_t eip_save = popd();
	struct emu_string *s_filename = popstring();
	printf("%x\tDeleteFileA(%s)\n",eip_save, emu_string_char(s_filename) );
	set_ret(0);
	emu_string_free(s_filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ExitProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   /* VOID WINAPI ExitProcess(UINT uExitCode); */
	/* VOID ExitThread(DWORD dwExitCode); */
	uint32_t eip_save = popd();
	uint32_t exitcode = popd();
	printf("%x\t%s(%i)\n", eip_save, ex->fnname, exitcode);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	opts.steps = 0;
	return 0;
}

int32_t	__stdcall hook_exit(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   /* cdecl void exit (int status); */
	uint32_t eip_save = popd();
	uint32_t exitcode = get_arg(0);
	printf("%x\t%s(%i)\n", eip_save, ex->fnname, exitcode);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	opts.steps = 0;
	return 0;
}


int32_t	__stdcall hook_CloseHandle(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* BOOL CloseHandle( HANDLE hObject);*/
	uint32_t eip_save = popd();
	uint32_t object = popd();
	set_ret(1);
	printf("%x\tCloseHandle(%x)\n", eip_save, object);
	if(opts.interactive_hooks == 1) set_ret( CloseHandle((HANDLE)object) );
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CreateFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	uint32_t eip_save = popd();
	struct emu_string *filename = isWapi(ex->fnname) ? popwstring() :  popstring();
	uint32_t desiredaccess = popd();
	uint32_t sharemode = popd();
	uint32_t securityattr = popd();
    uint32_t createdisp = popd();
	uint32_t flagsandattr = popd();
	uint32_t templatefile = popd();

	char *localfile = 0;

	if( opts.CreateFileOverride ){ 
		if( (int)opts.h_fopen == 0){
			printf("\tOpening a valid handle to %s\n", filename->data);
			HANDLE f = CreateFile(filename->data, GENERIC_READ|GENERIC_WRITE ,0,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0); 
			set_ret((int)f);
		}else{
			set_ret((int)opts.h_fopen);
		}
	}else{
		if(opts.interactive_hooks == 1 ){
			localfile = SafeTempFile();
			HANDLE f = CreateFile(localfile, GENERIC_READ|GENERIC_WRITE ,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0); 
			set_ret((int)f);
		}else{
			set_ret( get_fhandle() );
		}
	}
	
	printf("%x\t%s(%s) = %x\n", eip_save, ex->fnname, emu_string_char(filename), cpu->reg[eax]  );

	if(!opts.CreateFileOverride && opts.interactive_hooks){
		start_color(myellow);
		printf("\tInteractive mode local file %s\n", localfile);
		end_color();
	}

	opts.CreateFileOverride = false;

	emu_string_free(filename);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_CreateProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*BOOL CreateProcess( 
  LPCWSTR pszImageName, 
  LPCWSTR pszCmdLine, 
  LPSECURITY_ATTRIBUTES psaProcess, 
  LPSECURITY_ATTRIBUTES psaThread, 
  BOOL fInheritHandles, 
  DWORD fdwCreate, 
  LPVOID pvwinironment, 
  LPWSTR pszCurDir, 
  LPSTARTUPINFOW psiStartInfo, 
  LPPROCESS_INFORMATION pProcInfo
);*/
	uint32_t eip_save = popd();
	struct emu_string *imagename = isWapi(ex->fnname) ? popwstring() :  popstring();
	struct emu_string *command = isWapi(ex->fnname) ? popwstring() :  popstring();
	uint32_t p_process = popd();
	uint32_t p_thread = popd();
	uint32_t inherithandles = popd();
	uint32_t create = popd();
	uint32_t winironment = popd();
	uint32_t cwd = popd();
	uint32_t p_startinfo = popd();
	uint32_t p_procinfo = popd();

	STARTUPINFO *si = (STARTUPINFO*)malloc(sizeof(STARTUPINFO));
	memset(si, 0, sizeof(STARTUPINFO));

	emu_memory_read_dword(mem, p_startinfo + 14 * 4, (uint32_t *)&si->hStdInput);
	emu_memory_read_dword(mem, p_startinfo + 15 * 4, (uint32_t *)&si->hStdOutput);
	emu_memory_read_dword(mem, p_startinfo + 16 * 4, (uint32_t *)&si->hStdError);

	PROCESS_INFORMATION *pi = (PROCESS_INFORMATION*)malloc(sizeof(PROCESS_INFORMATION));
	memset(pi, 0, sizeof(PROCESS_INFORMATION));

	pi->hProcess = (HANDLE)4713;
	pi->hThread = (HANDLE)4714;
	pi->dwProcessId = 4711;
	pi->dwThreadId = 4712;

	emu_memory_write_dword(mem, p_procinfo+0*4, (uint32_t)pi->hProcess);
	emu_memory_write_dword(mem, p_procinfo+1*4, (uint32_t)pi->hThread);
	emu_memory_write_dword(mem, p_procinfo+2*4, pi->dwProcessId);
	emu_memory_write_dword(mem, p_procinfo+3*4, pi->dwThreadId);
	emu_memory_write_dword(mem, p_procinfo+0*4, (uint32_t)pi->hProcess);
	emu_memory_write_dword(mem, p_procinfo+1*4, (uint32_t)pi->hThread);
	emu_memory_write_dword(mem, p_procinfo+2*4, pi->dwProcessId);
	emu_memory_write_dword(mem, p_procinfo+3*4, pi->dwThreadId);

	char* pszCmdLine = emu_string_char(command);
	char* pszImageName = emu_string_char(imagename);

	if(imagename->emu_offset == 0 && pszCmdLine[0] == 0){
		//some shellcode uses the function prolog of CreateProcess to put stack inline..
		struct emu_string *cmd = emu_string_new();
		emu_memory_read_string(mem, cpu->reg[ebp] , cmd, 255);
		printf("%x\t%s( %s ) = 0x1269 (ebp)\n",eip_save, ex->fnname, (char*)cmd->data);
		emu_string_free(cmd);
	}else{
		printf("%x\t%s( %s, %s ) = 0x1269\n",eip_save, ex->fnname, pszCmdLine, pszImageName );
	}

	set_ret(0x1269);
	emu_string_free(imagename);
	emu_string_free(command);
	free(pi);
	free(si);

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_GetVersion(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* DWORD WINAPI GetVersion(void); */
	uint32_t eip_save = popd();
	uint32_t version = 0xa280105;
	set_ret(version);
	printf("%x\tGetVersion()\n", eip_save);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetProcAddress(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{ /* FFARPROC WINAPI GetProcAddress(  HMODULE hModule,  LPCSTR lpProcName);*/
	uint32_t eip_save = popd();
	uint32_t module = popd();
	struct emu_string *procname = popstring();

	uint32_t ordinal = 0;
	uint32_t index  = 0;
	int i;
	bool invalid = false;
	set_ret(0); //set default value of 0 (not found) //dzzie		

	for ( i=0; win->loaded_dlls[i] != NULL; i++ )
	{
		struct emu_env_w32_dll* dll = win->loaded_dlls[i];

		if ( dll->baseaddr == module )
		{
			if( procname->size == 0 ){ //either an error or an ordinal
				ordinal = procname->emu_offset;
				struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_ordinal, (void *)ordinal);
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}else{
				struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnname, (void *)emu_string_char(procname));
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
				//logDebug(win->emu, "found %s at addr %08x\n",emu_string_char(procname), dll->baseaddr + hook->hook.win->virtualaddr );
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}
		}	
	}

	if(ordinal==0){
		printf("%x\tGetProcAddress(%s)\n",eip_save, emu_string_char(procname));
	}else{
		char buf[255]={0};
		fulllookupAddress(cpu->reg[eax], &buf[0]); 
		printf("%x\tGetProcAddress(%s.0x%x) - %s \n",eip_save, dllFromAddress(module), ordinal, buf);
	}

	if(module == 0 || cpu->reg[eax] == 0 ) printf("\tLookup not found: module base=%x dllName=%s\n", module, dllFromAddress(module) );  

	emu_string_free(procname);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetSystemDirectoryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* UINT GetSystemDirectory(   LPTSTR lpBuffer,   UINT uSize ); */
	uint32_t eip_save = popd();
	uint32_t p_buffer = popd();
	uint32_t size = popd();
	static char *sysdir = "c:\\WINDOWS\\system32";
	emu_memory_write_block(mem, p_buffer, sysdir, 20);
	set_ret(19);
	printf("%x\tGetSystemDirectoryA( c:\\windows\\system32\\ )\n",eip_save);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_malloc(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* cdecl void *malloc( size_t size );  not stdcall! */
	uint32_t eip_save = popd();
	uint32_t size = get_arg(0);

	if(size > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		size = MAX_ALLOC; //dzzie
	}

	uint32_t baseMemAddress = next_alloc;
	set_next_alloc(size); // so dump knows about it...
		
	void *buf = malloc(size);
	memset(buf,0,size);
	emu_memory_write_block(mem,baseMemAddress,buf, size);
	free(buf);
	 
	set_ret(baseMemAddress);
	printf("%x\tmalloc(%x)\n",eip_save,size);	
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_memset(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* cdecl void * memset( void* dest, int c, size_t count ); (handles both ntdll and msvcrt) */
	uint32_t eip_save = popd();
	uint32_t dest = get_arg(0);
	uint32_t writeme = get_arg(4);
	uint32_t size = get_arg(8);

	printf("%x\tmemset(buf=%x, c=%x, sz=%x)\n",eip_save,dest,writeme,size);

	if(size > 0 && size < MAX_ALLOC){
		void* buf = malloc(size);
		memset(buf, writeme, size);
		emu_memory_write_block(mem, dest, buf, size);
	}

	set_ret(dest);
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SetUnhandledExceptionFilter(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);*/
	uint32_t eip_save = popd();
	uint32_t lpfilter = popd();

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

int32_t	__stdcall hook_WaitForSingleObject(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*DWORD WINAPI WaitForSingleObject(  HANDLE hHandle,  DWORD dwMilliseconds);*/
	uint32_t eip_save = popd();
	uint32_t handle = popd();
	uint32_t msecs = popd();

	uint32_t returnvalue = 0;
	printf("%x\tWaitForSingleObject(h=%x, ms=%x)\n",eip_save, (int)handle, msecs);
	if(opts.interactive_hooks){
		returnvalue = WaitForSingleObject((HANDLE)handle, msecs);	
	}
	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_WriteFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
	BOOL WriteFile(
	  HANDLE hFile,
	  LPCVOID lpBuffer,
	  DWORD nNumberOfBytesToWrite,
	  LPDWORD lpNumberOfBytesWritten,
	  LPOVERLAPPED lpOverlapped
	);
*/  
	uint32_t eip_save = popd();
	uint32_t file = popd();
	uint32_t p_buffer = popd();
	uint32_t bytestowrite = popd();
	uint32_t p_byteswritten = popd();
	uint32_t p_overlapped = popd();

	uint32_t max_size = 0x900000;
	if( bytestowrite > max_size ){  //sample 2c2167d371c6e0ccbcee778a4d10b3bd - dzzie 
		if(!opts.norw) printf("\tWriteFile modifying BytesToWrite from %x to %x\n", bytestowrite , max_size);
		bytestowrite = max_size;
	}

	unsigned char *buffer = (unsigned char*)malloc(bytestowrite);
	emu_memory_read_block(mem, p_buffer,(void*) buffer, bytestowrite);

	emu_memory_write_dword(mem, p_byteswritten, bytestowrite);

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

	bool isSpam = strcmp(win->lastApiCalled, "WriteFile") == 0 ? true : false;

	if(!isSpam && !opts.norw)
		printf("%x\tWriteFile(h=%x, buf=%x, len=%x, lpw=%x, lap=%x) = %x\n",eip_save, (int)file, p_buffer, bytestowrite, p_byteswritten,p_overlapped, returnvalue );
	
	if(isSpam && win->lastApiHitCount == 2) printf("\tHiding repetitive WriteFile calls\n");

	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_VirtualProtect(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*
  BOOL VirtualProtect( 
 	   LPVOID lpAddress, 
 	   DWORD  dwSize, 
       DWORD  flNewProtect, 
       PDWORD lpflOldProtect 
  ); 
*/
	uint32_t eip_save = popd();
	uint32_t p_address = popd();
	uint32_t size = popd();
	uint32_t newprotect = popd();
	uint32_t oldprotect = popd();

	char lookup[300];
	int rv = fulllookupAddress( p_address, &lookup[0]);
	if( rv != 1) sprintf(lookup, "%x", p_address);

	printf("%x\tVirtualProtect(adr=%s, sz=%x, flags=%x)\n", eip_save, lookup, size ,newprotect);

	set_ret(1);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

//*************************************************************************************
//winsock hooks

int32_t	__stdcall hook_accept(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*SOCKET accept(
  SOCKET s,
  struct sockaddr* addr,
  int* addrlen
);*/
	uint32_t eip_save = popd();
	uint32_t s  = popd();
	uint32_t addr = popd();
	uint32_t addrlen = popd();
	
	struct sockaddr sa;
	emu_memory_read_block(mem, addr, &sa, sizeof(struct sockaddr));

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_bind(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int bind(   SOCKET s,  const struct sockaddr* name,  int namelen); */
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t p_name = popd();
	uint32_t namelen = popd();
	
	struct sockaddr sa;
	emu_memory_read_block(mem, p_name, &sa, sizeof(struct sockaddr));

	if (namelen != sizeof(struct sockaddr)) namelen = sizeof(struct sockaddr);

	uint32_t returnvalue = 21 ;
	if(opts.interactive_hooks == 1) returnvalue = bind((SOCKET)s, &sa, namelen);

	printf("%x\tbind(h=%x, port:%d, sz=%x) = %x\n",eip_save, s, get_client_port(&sa),namelen, returnvalue );

	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_closesocket(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   /*int closesocket(SOCKET s);*/
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t returnvalue = 0;
	printf("%x\tclosesocket(h=%x)\n",eip_save, s );
	if(opts.interactive_hooks == 1 ) returnvalue = closesocket((SOCKET)s);
	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_connect(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{	/* int connect(  SOCKET s,  const struct sockaddr* name,  int namelen)*/
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t p_name = popd();
	uint32_t namelen = popd();

	struct sockaddr sa;
	emu_memory_read_block(emu_memory_get(win->emu), p_name, &sa, sizeof(struct sockaddr));
	
	//we want this displayed before the connect attempt, showing org data, and overrides if used..8.5.13
	printf("%x\tconnect(h=%x, host: %s , port: %d ) = %x\n",eip_save, s, get_client_ip(&sa), get_client_port(&sa), cpu->reg[eax]  );

	if (opts.override.host != NULL ){
		struct sockaddr_in *si = (struct sockaddr_in *)&sa;
		si->sin_addr.s_addr = inet_addr(opts.override.host);
		start_color(colors::myellow);
		if (opts.override.port > 0){
			struct sockaddr_in *si = (struct sockaddr_in *)&sa;;
			si->sin_port = htons(opts.override.port);
			printf("\tOverriding to: %s:%d\n",opts.override.host, opts.override.port);
		}else{
			printf("\tOverriding to: %s\n",opts.override.host);
		}
		end_color();
	}

	if (namelen != sizeof(struct sockaddr)) namelen = sizeof(struct sockaddr);

	if( opts.interactive_hooks == 0 ){
		set_ret(0x4711);
	}else{
		set_ret( connect((SOCKET)s, &sa, namelen) );
	}

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_listen(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int listen(   SOCKET s,  int backlog);*/
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t backlog = popd();

	uint32_t returnvalue = 0x21;	
	if(opts.interactive_hooks == 1 ) returnvalue = listen((SOCKET)s, backlog);

	printf("%x\tlisten(h=%x) = %x\n",eip_save,s,returnvalue);

	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_recv(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int recv(  SOCKET s,  char* buf,  int len,  int flags);*/
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t buf = popd();
	uint32_t len = popd();
	uint32_t flags = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_send(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int send(  SOCKET s,  const char* buf,  int len,  int flags);*/
	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t p_buf = popd();
	uint32_t len = popd();
	uint32_t flags = popd();

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
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}



int32_t	__stdcall hook_sendto(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int sendto(  SOCKET s,  const char* buf,  int len,  int flags,  const struct sockaddr* to,  int tolen);*/

	uint32_t eip_save = popd();
	uint32_t s = popd();
	uint32_t p_buf = popd();
	uint32_t len = popd();
	uint32_t flags = popd();
	uint32_t p_to = popd();
	uint32_t tolen = popd();

	if(len > MAX_ALLOC){
		printf("\tAllocation > MAX_ALLOC adjusting...\n");
		len = MAX_ALLOC; //dzzie
	}
	
	char *buffer = (char *)malloc(len);
	emu_memory_read_block(emu_memory_get(win->emu), p_buf, buffer, len);

	struct sockaddr sa;
	emu_memory_read_block(emu_memory_get(win->emu), p_to, &sa, sizeof(struct sockaddr));

	uint32_t returnvalue = len;	
	printf("%x\tsendto(h=%x, buf=%x, host: %s, port: %x)\n",eip_save, s, p_buf, get_client_ip(&sa), get_client_port(&sa) );

	if(opts.interactive_hooks ==1) returnvalue = sendto((SOCKET)s,buffer,len,flags,&sa,tolen);

	set_ret(returnvalue);
	free(buffer);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_socket(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*SOCKET WSAAPI socket(  int af,  int type,  int protocol);*/
	uint32_t eip_save = popd();
	uint32_t af = popd();
	uint32_t type = popd();
	uint32_t protocol = popd();

	uint32_t returnvalue = 65;
	if(opts.interactive_hooks == 1 ){
		returnvalue = (int)socket(af, type, protocol);
	}

	printf("%x\tsocket(%i, %i, %i) = %x\n",eip_save, af, type, protocol, returnvalue);

	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}



int32_t	__stdcall hook_WSASocketA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* SOCKET WSASocket(
	  int af,
	  int type,
	  int protocol,
	  LPWSAPROTOCOL_INFO lpProtocolInfo,
	  GROUP g,
	  DWORD dwFlags
); */
	uint32_t eip_save = popd();
	uint32_t af = popd();
	uint32_t type = popd();
	uint32_t protocol = popd();
	uint32_t protocolinfo = popd();
	uint32_t group = popd();
	uint32_t flags  = popd();
	
	uint32_t returnvalue = 66;
	printf("%x\tWSASocket(af=%i, tp=%i, proto=%i, group=%i, flags=%i)\n", eip_save, af, type, protocol,group,flags);

	if(opts.interactive_hooks == 1 ) returnvalue = socket(af, type, protocol);

	set_ret(returnvalue);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}



int32_t	__stdcall hook_WSAStartup(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/*int WSAStartup(  WORD wVersionRequested,  LPWSADATA lpWSAData);*/
	uint32_t eip_save = popd();
	uint32_t wsaversionreq = popd();
	uint32_t wsadata = popd();
	printf("%x\tWSAStartup(%x)\n", eip_save, wsaversionreq);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CreateFileMappingA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_WideCharToMultiByte(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
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
	uint32_t a[10] = {0,0,0,0,0,0,0,0,0,0};
	loadargs(8, a);
	
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

int32_t	__stdcall hook_GetLogicalDriveStringsA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		DWORD WINAPI GetLogicalDriveStrings(
		  __in   DWORD nBufferLength,
		  __out  LPTSTR lpBuffer
		);
	*/

	uint32_t rv = 0;
	uint32_t eip_save = popd();
	uint32_t bufInSz = popd();
	uint32_t bufIn = popd();
	
	//0012F304  41 3A 5C 00 43 3A 5C 00  A:\.C:\.
	//0012F30C  44 3A 5C 00 00 00 00 00  D:\.....
	if( bufInSz >=8){
		emu_memory_write_dword(mem,bufIn, 0x005C3A43);
		emu_memory_write_dword(mem,bufIn+4, 0x005C3A43);
		rv = 8;
	}

	printf("%x\tGetLogicalDriveStringsA(sz=%x, buf=%x) = %x\n", eip_save, bufInSz , bufIn ,rv);

	set_ret(rv);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_FindWindowA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_DeleteUrlCacheEntryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_FindFirstFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
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

int32_t	__stdcall hook_shdocvw65(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   //ordinal 101 = IEWinMain http://www.kakeeware.com/i_launchie.php
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
	emu_string_free(sCmdLine);

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

int32_t	__stdcall hook_GetUrlCacheEntryInfoA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
	BOOL GetUrlCacheEntryInfo(
		  __in     LPCTSTR lpszUrlName,
		  __out    LPINTERNET_CACHE_ENTRY_INFO lpCacheEntryInfo,
		  __inout  LPDWORD lpcbCacheEntryInfo
	);
	*/

	uint32_t eip_save = popd();
	struct emu_string* sUrl = popstring();
	uint32_t entry_info = popd();
	uint32_t lpSize = popd();

	uint32_t size = 0;
	emu_memory_read_dword(mem, lpSize, &size);

	INTERNET_CACHE_ENTRY_INFO entry;
	char* filePath = "c:\\cache_local_file.swf";

	printf("%x\tGetUrlCacheEntryInfoA(%s, buf=%x, sz=%x)\n", eip_save, sUrl->data, entry_info, size );
	
	emu_memory_write_block(mem, safe_stringbuf, (void*)filePath, strlen(filePath));
	memset(&entry, 1, sizeof(entry));
	entry.dwStructSize = sizeof(entry);
	entry.lpszLocalFileName = (char*)safe_stringbuf;
	entry.dwSizeHigh = 0;
	entry.dwSizeLow = 86,784;
	entry.dwHitRate = 2;
	entry.dwUseCount = 2;
	entry.CacheEntryType = NORMAL_CACHE_ENTRY;
	emu_memory_write_block(mem, entry_info,(void*)&entry,sizeof(entry));

	//dont ask me why it just is what they wanted...
	uint32_t rv = emu_memory_write_block(mem, entry_info+0x74 ,(void*)filePath,strlen(filePath) );
	
	set_ret(1);
	emu_string_free(sUrl);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CopyFileA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
	BOOL WINAPI CopyFile(
	  __in  LPCTSTR lpExistingFileName,
	  __in  LPCTSTR lpNewFileName,
	  __in  BOOL bFailIfExists
	);
	*/

	uint32_t eip_save = popd();
	struct emu_string* sFrom = popstring();
	struct emu_string* sTo = popstring();
	uint32_t failExists = popd();

	printf("%x\tCopyFileA(%s, %s)\n", eip_save, sFrom->data, sTo->data );
	
	set_ret(1);
	emu_string_free(sFrom);
	emu_string_free(sTo);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetFileSize(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
/*
	DWORD WINAPI GetFileSize(
	  __in       HANDLE hFile,
	  __out_opt  LPDWORD lpFileSizeHigh
	);

	BOOL WINAPI GetFileSizeEx(
	  __in   HANDLE hFile,
	  __out  PLARGE_INTEGER lpFileSize
	);
*/

	uint32_t eip_save = popd();
	uint32_t hFile = popd();
	uint32_t lpSizeHigh = popd();

	uint32_t ret_val = -1;
	uint32_t sizeHigh = 0;
    bool nolog = false;

	if( hFile < 5 && opts.h_fopen > 0 )
		ret_val = opts.fopen_fsize + opts.adjust_getfsize;
	else
		ret_val = GetFileSize( (HANDLE)hFile, &sizeHigh) + opts.adjust_getfsize;
		
	bool isSpam = strcmp(win->lastApiCalled, "GetFileSize") == 0 ? true : false;

	if(!isSpam || (isSpam && win->lastApiHitCount == 2) )
		printf("%x\tGetFileSize(%x, %x) = %x\n", eip_save, hFile, lpSizeHigh, ret_val );
	
	if(isSpam && win->lastApiHitCount == 2) printf("\topen file handle scanning occuring - hiding output\n");

	if(lpSizeHigh!=0) emu_memory_write_dword(mem, lpSizeHigh, sizeHigh);
	
	set_ret(ret_val);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_EnumWindows(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
		BOOL WINAPI EnumWindows(
		  __in  WNDENUMPROC lpEnumFunc,
		  __in  LPARAM lParam
		);
	*/

	uint32_t eip_save = popd();
	uint32_t lpfnEnum = popd();
	uint32_t lParam = popd();

	 
	printf("%x\tEnumWindows(lpfn=%x, param=%x)\n", eip_save, lpfnEnum, lParam );

	if( lpfnEnum != 0 ){ 
		//BOOL CALLBACK EnumWindowsProc(HWND hwnd,LPARAM lParam);
		uint32_t hwnd = 0xDEADBEEF;
		pushd(lParam);
		pushd(hwnd);      //possible error in my sample..
		pushd(eip_save);
		emu_cpu_eip_set(cpu, lpfnEnum);
		printf("\tTransferring execution to EnumWindowsProc...\n");
	}else{
		cpu->reg[eax] = 0;
		emu_cpu_eip_set(cpu, eip_save);
	}

	return 0;
}

int32_t	__stdcall hook_GetClassNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
		int WINAPI GetClassName(
		  __in   HWND hWnd,
		  __out  LPTSTR lpClassName,
		  __in   int nMaxCount
		);
	*/

	uint32_t eip_save = popd();
	uint32_t hwnd = popd();
	uint32_t lpBuf = popd();
    uint32_t size = popd();
	 
	printf("%x\tGetClassName(hwnd=%x, lpBuf=%x, size=%x)\n", eip_save, hwnd, lpBuf, size );

	char* className = "NoSoupForYou!";
	//char* className = "OLLYDBG";
	int slen = strlen(className);

	if(slen >= size){
		emu_memory_write_block(mem, lpBuf, (void*)className, slen);
		cpu->reg[eax] = slen-1;
	}else{
		slen=0;
	}
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_fread(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
		size_t fread ( void * ptr, size_t size, size_t count, FILE * stream );. 
	*/

	uint32_t eip_save = popd(); 
	uint32_t lpData = get_arg(0);   // untested! bugfix was popd() but is cdecl 3.20.13
	uint32_t size = get_arg(4);
    uint32_t count = get_arg(8);
	uint32_t hFile = get_arg(12);

	uint32_t rv = count;
	uint32_t realSize = (size * count);

	if(opts.interactive_hooks == 1 && realSize > 0){
		if(realSize > MAX_ALLOC) realSize = MAX_ALLOC;
		void* realBuf = malloc(realSize+1);
		rv = fread(realBuf, size, count, (FILE*)hFile);
		if(rv > 0) emu_memory_write_block(mem, lpData, realBuf, realSize);
	}
	
	bool isSpam = strcmp(win->lastApiCalled, "fread") == 0 ? true : false;

	if(!isSpam)
		printf("%x\tfread(buf=%x, size=%x, cnt=%x, h=%x) = %x\n", eip_save, lpData, size, count, hFile, rv );
	
	if(isSpam && win->lastApiHitCount == 2) printf("\tHiding repetitive fread calls\n");
	
	set_ret(rv);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_IsBadReadPtr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*
		BOOL WINAPI IsBadReadPtr(
		  __in  const VOID *lp,
		  __in  UINT_PTR ucb
		);
	*/

	uint32_t eip_save = popd();
	uint32_t lpData = popd();
	uint32_t size = popd();
	uint32_t ret = 0; //success

	if(lpData <= 0x1000) ret--; //only time we will fail

	bool isSpam = strcmp(win->lastApiCalled, "IsBadReadPtr") == 0 ? true : false;

	if(!isSpam)
		printf("%x\tIsBadReadPtr(adr=%x, sz=%x)\n", eip_save, lpData, size );
	
	if(isSpam && win->lastApiHitCount == 2) printf("\tHiding repetitive IsBadReadPtr calls\n");
	
	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_GetCommandLineA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
	/*	LPTSTR WINAPI GetCommandLine(void);	*/

	uint32_t eip_save = popd();
	
	char* buf = opts.cmdline;
	if(buf == 0) buf = GetCommandLineA();
	uint32_t size = strlen(buf);
	emu_memory_write_block(mem, safe_stringbuf, (void*)buf, size);

	printf("%x\tGetCommandLineA() = %x\n", eip_save, safe_stringbuf );
	
	set_ret(safe_stringbuf);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetEnvironmentVariableA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		DWORD WINAPI GetEnvironmentVariable(
		  __in_opt   LPCTSTR lpName,
		  __out_opt  LPTSTR lpBuffer,
		  __in       DWORD nSize
		);	
	*/
	uint32_t eip_save = popd();
	struct emu_string* lpName = popstring();
	uint32_t buf = popd();
	uint32_t size = popd();

	char* var = lpName->data;
	
	char out[256]={0}; 

	if(stricmp(var, "ProgramFiles") == 0 ) strcpy(out, "C:\\Program Files");
	if(stricmp(var, "TEMP") == 0 )         strcpy(out, "C:\\Windows\\Temp");
	if(stricmp(var, "TMP") == 0 )          strcpy(out, "C:\\Windows\\Temp");
	if(stricmp(var, "WINDIR") == 0 )       strcpy(out, "C:\\Windows");

	int sl = strlen(out);
	if(sl < size) emu_memory_write_block(mem, buf, out, sl);
	emu_memory_write_byte(mem, buf+sl,0);
		
	printf("%x\tGetEnvironmentVariableA(name=%s, buf=%x, size=%x) = %s\n", eip_save, var, buf, size, out );

	emu_string_free(lpName);
	cpu->reg[eax] =  sl;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptAcquireContext(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptAcquireContext(
		  __out  HCRYPTPROV *phProv,
		  __in   LPCTSTR pszContainer,
		  __in   LPCTSTR pszProvider,
		  __in   DWORD dwProvType,
		  __in   DWORD dwFlags
		);

	*/
	uint32_t eip_save = popd();
	uint32_t phProv = popd();

	//if(strcmp(func, "CryptAcquireContextW") ==0 ){
		//handle unicode strings
	//}else{
		struct emu_string* szContainer = popstring();
		struct emu_string* szProvider = popstring();
	//}

	uint32_t dwProvType = popd();
	uint32_t dwFlags = popd();

	char out[1000] = {0};
	if( (dwFlags & CRYPT_VERIFYCONTEXT) > 0 ) strcat(out, "CRYPT_VERIFYCONTEXT");
	if( (dwFlags & CRYPT_NEWKEYSET) > 0 ) strcat(out, ", CRYPT_NEWKEYSET");
	if( (dwFlags & CRYPT_MACHINE_KEYSET) > 0  ) strcat(out, ", CRYPT_MACHINE_KEYSET ");
	if( (dwFlags & CRYPT_DELETEKEYSET) > 0 ) strcat(out, ", CRYPT_DELETEKEYSET");
	if( (dwFlags & CRYPT_SILENT) > 0 ) strcat(out, ", CRYPT_SILENT");
	if( (dwFlags & CRYPT_DEFAULT_CONTAINER_OPTIONAL ) > 0 ) strcat(out, ", CRYPT_DEFAULT_CONTAINER_OPTIONAL");
 
	HCRYPTPROV myProv = NULL; //typedef long
	
	uint32_t rv = (uint32_t)CryptAcquireContext(&myProv, szContainer->data, szProvider->data, dwProvType, dwFlags); 

	emu_memory_write_dword(mem, phProv, (uint32_t)myProv);
		
	printf("%x\t%s(%x, %s, %s, %x, %x) = %x mProv=%x\n", eip_save, ex->fnname, phProv, szContainer->data, szProvider->data, dwProvType, dwFlags, rv, (uint32_t)myProv );
	
	if(strlen(out) > 0) printf("\t Flags: %s\n", out);

	emu_string_free(szContainer);
	emu_string_free(szProvider);
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptCreateHash(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptCreateHash(
		  __in   HCRYPTPROV hProv,
		  __in   ALG_ID Algid,
		  __in   HCRYPTKEY hKey,
		  __in   DWORD dwFlags,
		  __out  HCRYPTHASH *phHash
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hProv = popd();
	uint32_t algid = popd();
	uint32_t hkey = popd();
	uint32_t flags = popd();
	uint32_t hHash = popd();

	HCRYPTHASH mHash;
	char sAlgid[256];
	GetAligIDName(algid, &sAlgid[0]);

	uint32_t rv = (uint32_t)CryptCreateHash(hProv,algid,hkey,flags,&mHash); 

	emu_memory_write_dword(mem, hHash, (uint32_t)mHash);
		
	printf("%x\tCryptCreateHash(%x, %s, %x, %x, %x) = %x mHash=%x\n", eip_save, hProv, sAlgid, hkey, flags, hHash, rv, (uint32_t)mHash );
	
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptHashData(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptHashData(
		  __in  HCRYPTHASH hHash,
		  __in  BYTE *pbData,
		  __in  DWORD dwDataLen,
		  __in  DWORD dwFlags
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hHash = popd();
	uint32_t pbData = popd();
	uint32_t dwDataLen = popd();
	uint32_t dwFlags = popd();

	uint32_t myDataLen = 1;
	if( dwDataLen < MAX_ALLOC) myDataLen = dwDataLen;

	unsigned char* data = (unsigned char*)malloc(myDataLen+1);
	emu_memory_read_block(mem, pbData, data, myDataLen);

	uint32_t rv = (uint32_t)CryptHashData(hHash,data,myDataLen,dwFlags); 
		
	printf("%x\tCryptHashData(%x, %x, %x, %x) = %x\n", eip_save, hHash, pbData, dwDataLen, dwFlags,rv);
	if(myDataLen == 1) printf("\tSize excedded max alloc, was ignored...\n");

	free(data);
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptGetHashParam(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptGetHashParam(
		  __in     HCRYPTHASH hHash,
		  __in     DWORD dwParam,
		  __out    BYTE *pbData,
		  __inout  DWORD *pdwDataLen,
		  __in     DWORD dwFlags
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hHash = popd();
	uint32_t dwParam = popd();
	uint32_t pbData = popd();
	uint32_t pdwDataLen = popd();
	uint32_t dwFlags = popd();

	uint32_t dwDataLen = 0;
	uint32_t myDataLen = 0;

	emu_memory_read_dword(mem, pdwDataLen, &dwDataLen);

	if( dwDataLen < MAX_ALLOC) myDataLen = dwDataLen;
	unsigned char* myData = (unsigned char*)malloc(myDataLen+1);

	uint32_t rv = (uint32_t)CryptGetHashParam(hHash,dwParam,myData, &myDataLen,dwFlags); 
		
	printf("%x\tCryptGetHashParam(%x, %x, %x, %x, %x) = %x\n", eip_save, hHash, dwParam, pbData, pdwDataLen, dwFlags,rv);
	if(myDataLen == 0) printf("\tSize %x excedded max alloc, was ignored...\n", dwDataLen);

	emu_memory_write_block(mem, pbData, myData, myDataLen);
	emu_memory_write_dword(mem, dwDataLen, myDataLen);

	free(myData);
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptDestroyHash(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptDestroyHash(
		  __in  HCRYPTHASH hHash
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hHash = popd();
	
	uint32_t rv = (uint32_t)CryptDestroyHash(hHash); 
		
	printf("%x\tCryptDestroyHash(%x)\n", eip_save, hHash);
	
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_CryptReleaseContext(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI CryptReleaseContext(
		  __in  HCRYPTPROV hProv,
		  __in  DWORD dwFlags
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hProv = popd();
	uint32_t dwFlags = popd();
	
	uint32_t rv = (uint32_t)CryptReleaseContext(hProv,dwFlags); 
		
	printf("%x\tCryptReleaseContext(%x, %x)\n", eip_save, hProv,dwFlags);
	
	cpu->reg[eax] =  rv;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_InternetConnectA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		HINTERNET InternetConnect(
		  __in  HINTERNET hInternet,
		  __in  LPCTSTR lpszServerName,
		  __in  INTERNET_PORT nServerPort,
		  __in  LPCTSTR lpszUsername,
		  __in  LPCTSTR lpszPassword,
		  __in  DWORD dwService,
		  __in  DWORD dwFlags,
		  __in  DWORD_PTR dwContext
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hInternet = popd();
	struct emu_string* server = popstring();
	uint32_t port = popd();
	struct emu_string* user = popstring();
	struct emu_string* pass = popstring();
	uint32_t service = popd();
	uint32_t flags = popd();
	uint32_t context = popd();

	printf("%x\tInternetConnectA(server: %s, port: %d, ", eip_save, server->data , port);
	if( user->size > 0) printf("user: %s, ", user->data);
	if( pass->size > 0) printf("pass: %s ", pass->data);
	printf(")\n");

	emu_string_free(server);
	emu_string_free(user);
	emu_string_free(pass);
	cpu->reg[eax] =  0x4892;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}
	
int32_t	__stdcall hook_HttpOpenRequestA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		HINTERNET HttpOpenRequest(
		  __in  HINTERNET hConnect,
		  __in  LPCTSTR lpszVerb,
		  __in  LPCTSTR lpszObjectName,
		  __in  LPCTSTR lpszVersion,
		  __in  LPCTSTR lpszReferer,
		  __in  LPCTSTR *lplpszAcceptTypes,
		  __in  DWORD dwFlags,
		  __in  DWORD_PTR dwContext
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hInternet = popd();
	struct emu_string* verb = popstring();
	struct emu_string* objname = popstring();
	struct emu_string* version = popstring();
	struct emu_string* refer = popstring();
	uint32_t accept = popd();
	uint32_t flags = popd();
	uint32_t context = popd();

	printf("%x\tHttpOpenRequestA(", eip_save);
	if(verb->size > 0) printf("verb: %s, ", verb->data);
	if(objname->size > 0) printf("path: %s, ", objname->data);
	if(version->size > 0) printf("version: %s, ", version->data);
	if(refer->size > 0) printf("referrer: %s", refer->data);
	printf(")\n");

	emu_string_free(verb);
	emu_string_free(objname);
	emu_string_free(version);
	emu_string_free(refer);

	cpu->reg[eax] =  0x4893;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_HttpSendRequestA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL HttpSendRequest(
		  __in  HINTERNET hRequest,
		  __in  LPCTSTR lpszHeaders,
		  __in  DWORD dwHeadersLength,
		  __in  LPVOID lpOptional,
		  __in  DWORD dwOptionalLength
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hInternet = popd();
	struct emu_string* headers = popstring();
	uint32_t hLen = popd();
	struct emu_string* opt = popstring();
	uint32_t optLen = popd();

	printf("%x\tHttpSendRequestA(", eip_save);
	if(headers->size != 0) printf("%s, ", headers->data);
	if(optLen != 0) printf("opt: %s", opt->data);
	printf(")\n");

	emu_string_free(headers);
	emu_string_free(opt);
	
	cpu->reg[eax] =  0x4893;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_InternetReadFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL InternetReadFile(
		  __in   HINTERNET hFile,
		  __out  LPVOID lpBuffer,
		  __in   DWORD dwNumberOfBytesToRead,
		  __out  LPDWORD lpdwNumberOfBytesRead
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hInternet = popd();
	uint32_t buf = popd();
	uint32_t readSize = popd();
	uint32_t bytesRead = popd();

	bool isSpam = strcmp(win->lastApiCalled, "InternetReadFile") == 0 ? true : false;
	
	if(!isSpam) printf("%x\tInternetReadFile(%x, buf: %x, size: %x)\n", eip_save, hInternet, buf, readSize);
	//emu_memory_write_dword(mem, bytesRead, readSize);
	
	cpu->reg[eax] = TRUE;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_RegOpenKeyEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		LONG WINAPI RegOpenKeyEx(
		  __in        HKEY hKey,
		  __in_opt    LPCTSTR lpSubKey,
		  __reserved  DWORD ulOptions,
		  __in        REGSAM samDesired,
		  __out       PHKEY phkResult
		);
	*/
	uint32_t eip_save = popd();
	char* hKey = getHive( popd() );
	struct emu_string* subKey = isWapi(ex->fnname) ? popwstring() : popstring();
	uint32_t opt = popd();
	uint32_t sam = popd();
	uint32_t result = popd();
	
	printf("%x\t%s(%s, %s)\n", eip_save, ex->fnname , hKey, subKey->data );
	emu_memory_write_dword(mem, result, 0);
	
	emu_string_free(subKey);
	cpu->reg[eax] = -1;//ERROR_SUCCESS;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_OpenSCManager(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		SC_HANDLE WINAPI OpenSCManager(
		  __in_opt  LPCTSTR lpMachineName,
		  __in_opt  LPCTSTR lpDatabaseName,
		  __in      DWORD dwDesiredAccess
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* machine = isWapi(ex->fnname) ? popwstring() : popstring();
	struct emu_string* db = isWapi(ex->fnname) ? popwstring() : popstring();
	uint32_t access = popd();
	
	printf("%x\t%s(%s, %s, %x)\n", eip_save, ex->fnname, machine->data, db->data, access );
	
	emu_string_free(machine);
	emu_string_free(db);
	cpu->reg[eax] = 0x123456; 	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_OpenService(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		SC_HANDLE WINAPI OpenService(
		  __in  SC_HANDLE hSCManager,
		  __in  LPCTSTR lpServiceName,
		  __in  DWORD dwDesiredAccess
		);
	*/

	uint32_t eip_save = popd();
	uint32_t hSc = popd();
	struct emu_string* name = isWapi(ex->fnname) ?  popwstring() : popstring();
	uint32_t access = popd();
	
	printf("%x\t%s(%s)\n", eip_save, ex->fnname, name->data);
	
	emu_string_free(name);
	cpu->reg[eax] = -1; 	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ControlService(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		BOOL WINAPI ControlService(
		  __in   SC_HANDLE hService,
		  __in   DWORD dwControl,
		  __out  LPSERVICE_STATUS lpServiceStatus
		);
	*/

	uint32_t eip_save = popd();
	uint32_t hSc = popd();
	uint32_t control = popd();
	uint32_t status = popd();
	
	printf("%x\t%s(%x)\n", eip_save, ex->fnname, control);
	
	cpu->reg[eax] = 0; 	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_QueryDosDeviceA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		DWORD WINAPI QueryDosDevice(
		  __in_opt  LPCTSTR lpDeviceName,
		  __out     LPTSTR lpTargetPath,
		  __in      DWORD ucchMax
		);
	*/
	uint32_t eip_save = popd();
	struct emu_string* name = popstring();
	uint32_t buf = popd();
	uint32_t size = popd();

	uint32_t retval=0;
	char* hdd  = "\\Device\\HarddiskVolume1\x00\x00";
	char* flop = "\\Device\\Floppy0\x00\x00";
	char* tmp  = NULL;

	printf("%x\tQueryDosDeviceA(%s, buf: %x, size: %x)\n", eip_save, name->data, buf, size);
	
	tmp = strcmp(name->data, "A:")==0 ? flop : hdd;  

	retval = strlen(tmp)+2;
	if(size < retval){
		emu_memory_write_block(mem, buf,tmp, retval);
	}else{
		retval = ERROR_INSUFFICIENT_BUFFER;
	}
	
	cpu->reg[eax] = retval;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_lstrcatA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  LPTSTR WINAPI lstrcat(
		  __inout  LPTSTR lpString1,
		  __in     LPTSTR lpString2
		);
		and ntdll.strcat
	*/
	uint32_t eip_save = popd();
	struct emu_string* s1 = popstring();
	struct emu_string* s2 = popstring();
	int i=0;

	printf("%x\t%s(%s, %s)\n", eip_save, ex->fnname , s1->data, s2->data);

	int sz = s1->size + s2->size + 10;
	char* buf = SafeMalloc(sz);
	
	if(s1->size > 0) strncpy(buf, s1->data, s1->size);
	if(s2->size > 0) lstrcatA(buf, s2->data);
	emu_memory_write_block(mem,s1->emu_offset,buf,strlen(buf)+1);
	free(buf);

	emu_string_free(s1);
	emu_string_free(s2);
	set_ret(s1->emu_offset); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_SHDeleteKeyA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  LSTATUS SHDeleteKey(
		  __in      HKEY hkey,
		  __in_opt  LPCTSTR pszSubKey
		);
	*/
	uint32_t eip_save = popd();
	uint32_t key = popd();
	struct emu_string* subKey = popstring();
	int i=0;

	printf("%x\tSHDeleteKeyA(%x, %s)\n", eip_save, key, subKey->data);
	
	emu_string_free(subKey);
	set_ret(ERROR_SUCCESS); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_CreateDirectoryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  BOOL WINAPI CreateDirectory(
		  __in      LPCTSTR lpPathName,
		  __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
		);
	*/
	uint32_t eip_save = popd();
	struct emu_string* s1 = popstring();
	uint32_t sec = popd();
	int i=0;

	printf("%x\tCreateDirectoryA(%s)\n", eip_save, s1->data);
	
	emu_string_free(s1);
	set_ret(TRUE); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_SetCurrentDirectoryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  BOOL WINAPI SetCurrentDirectory(
		  __in  LPCTSTR lpPathName
		);
	*/
	uint32_t eip_save = popd();
	struct emu_string* s1 = popstring();

	printf("%x\tSetCurrentDirectoryA(%s)\n", eip_save, s1->data);
	
	emu_string_free(s1);
	set_ret(1); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_InternetSetOption(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		BOOL InternetSetOption(
		  __in  HINTERNET hInternet,
		  __in  DWORD dwOption,
		  __in  LPVOID lpBuffer,
		  __in  DWORD dwBufferLength
		);

		option flags: http://msdn.microsoft.com/en-us/library/windows/desktop/aa385328(v=vs.85).aspx

	*/
	uint32_t eip_save = popd();
	uint32_t v1 = popd();
	uint32_t v2 = popd();
	uint32_t v3 = popd();
	uint32_t v4 = popd();

	printf("%x\t%s(h=%x, opt=%x, buf=%x, blen=%x)\n", eip_save, ex->fnname, v1,v2,v3,v4);
	
	set_ret(1); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_GetWindowThreadProcessId(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		DWORD WINAPI GetWindowThreadProcessId(
		  __in       HWND hWnd,
		  __out_opt  LPDWORD lpdwProcessId
		);

	*/
	uint32_t eip_save = popd();
	uint32_t v1 = popd();
	uint32_t v2 = popd();

	printf("%x\t%s(h=%x, buf=%x)\n", eip_save, ex->fnname, v1,v2);
	if(v2!=0) emu_memory_write_dword(mem,v2, 0x14077AC0);
	set_ret(0x14077AC0); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_OpenProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		HANDLE WINAPI OpenProcess(
		  __in  DWORD dwDesiredAccess,
		  __in  BOOL bInheritHandle,
		  __in  DWORD dwProcessId
		);
	*/

	uint32_t eip_save = popd();
	uint32_t v1 = popd();
	uint32_t v2 = popd();
	uint32_t pid = popd();

	char* proc = processNameForPid(pid);

	printf("%x\t%s(access=%x, inherit=%x, pid=%x) - Process: %s  \n", eip_save, ex->fnname, v1,v2,pid, proc);
	
	free(proc);
	set_ret(pid); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_ExpandEnvironmentStringsA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		DWORD WINAPI ExpandEnvironmentStrings(
		  __in       LPCTSTR lpSrc,
		  __out_opt  LPTSTR lpDst,
		  __in       DWORD nSize
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* src = popstring();
	uint32_t dst = popd();
	uint32_t sz = popd();

	printf("%x\t%s(%s, dst=%x, sz=%x)\n", eip_save, ex->fnname, src->data, dst,sz);
	
	char* buf = SafeMalloc(sz+1);
	int ret = ExpandEnvironmentStringsA(src->data, buf, sz);
	
	if(dst!=0 && ret!=0) emu_memory_write_block(mem,dst,buf,ret); 

	free(buf);
	emu_string_free(src);
	set_ret(ret); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_lstrlenA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		int WINAPI lstrlen(
		  __in  LPCTSTR lpString
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* src = popstring();

	printf("%x\t%s(%s)\n", eip_save, ex->fnname, src->data);
	
	int ret = lstrlenA(src->data);

	emu_string_free(src);
	set_ret(ret); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_lstrcmpiA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		int WINAPI lstrcmpi(
		  __in  LPCTSTR lpString1,
		  __in  LPCTSTR lpString2
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* src = popstring();
    struct emu_string* src2 = popstring();

	printf("%x\t%s(%s, %s)\n", eip_save, ex->fnname, src->data, src2->data);
	
	int ret = lstrcmpiA(src->data,src2->data);

	emu_string_free(src);
	emu_string_free(src2);
	set_ret(ret); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_memcpy(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		void * memcpy ( void * destination, const void * source, size_t num );

		VOID RtlMoveMemory(
		  _In_  VOID UNALIGNED *Destination,
		  _In_  const VOID UNALIGNED *Source,
		  _In_  SIZE_T Length
		);

	*/
	uint32_t eip_save = popd();
	uint32_t dest = popd();
	uint32_t src = popd();
	uint32_t sz = popd();

	printf("%x\t%s(dst=%x, src=%x, sz=%x)\n", eip_save, ex->fnname , dest, src, sz);

	void* buf = (void*)SafeMalloc(sz+1);
	emu_memory_read_block(mem, src, buf, sz);
	emu_memory_write_block(mem,dest, buf, sz);
	free(buf);
	
	set_ret(dest); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}


int32_t	__stdcall hook_lstrcpyA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		LPTSTR WINAPI lstrcpy( __out  LPTSTR lpString1, __in   LPTSTR lpString2);
	*/
	uint32_t eip_save = popd();
	uint32_t dest = popd();
	struct emu_string *str2 = popstring();
	
	printf("%x\t%s(dst=%x, src=%s)\n", eip_save, ex->fnname , dest, str2->data);

	emu_memory_write_block(mem, dest, str2->data, str2->size);
	emu_memory_write_byte(mem, dest+str2->size+1, 0);
	emu_string_free(str2);
	
	set_ret(dest); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_OpenEventA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		HANDLE WINAPI OpenEvent(
		  __in  DWORD dwDesiredAccess,
		  __in  BOOL bInheritHandle,
		  __in  LPCTSTR lpName
		);
	*/
	uint32_t eip_save = popd();
	uint32_t access = popd();
	uint32_t inherit = popd();
	struct emu_string *name = popstring();
	
	printf("%x\tOpenEventA(%s)\n", eip_save , name->data);

	emu_string_free(name);
	
	set_ret(0); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_CreateEventA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
		HANDLE WINAPI CreateEvent(
		  __in_opt  LPSECURITY_ATTRIBUTES lpEventAttributes,
		  __in      BOOL bManualReset,
		  __in      BOOL bInitialState,
		  __in_opt  LPCTSTR lpName
		);
	*/
	uint32_t eip_save = popd();
	uint32_t attrib = popd();
	uint32_t reset = popd();
	uint32_t init = popd();
	struct emu_string *name = popstring();
	
	printf("%x\tCreateEventA(%s)\n", eip_save , name->data);

	emu_string_free(name);
	
	set_ret(0x378298); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook__stricmp(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* _cdecl_ char *stricmp(const char *s1, const char *s2); */
	uint32_t eip_save  = popd();

	uint32_t pS1 = get_arg(0);
	struct emu_string *s1 = emu_string_new();
	emu_memory_read_string(mem, pS1, s1, 1256);

	uint32_t pS2 = get_arg(4);
	struct emu_string *s2 = emu_string_new();
	emu_memory_read_string(mem, pS2, s2, 1256);

	//struct emu_string *s1 = popstring();
	//struct emu_string *s2 = popstring();
	uint32_t ret=0;
	
	if(s1->size==0 || s2->size == 0){
		ret  = -1;
	}else{
		ret = stricmp(s1->data, s2->data);
	}

	printf("%x\t%s(%s, %s) = %x\n", eip_save, ex->fnname , s1->data, s2->data, ret);
	
	emu_string_free(s1);
	emu_string_free(s2);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_strcmp(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* char *strcmp(const char *s1, const char *s2); */
	uint32_t eip_save  = popd();
	struct emu_string *s1 = popstring();
	struct emu_string *s2 = popstring();
	uint32_t ret=0;
	
	if(s1->size==0 || s2->size == 0){
		ret  = -1;
	}else{
		ret = stricmp(s1->data, s2->data);
	}

	printf("%x\t%s(%s, %s) = %x\n", eip_save, ex->fnname , s1->data, s2->data, ret);
	
	emu_string_free(s1);
	emu_string_free(s2);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetThreadContext(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
		BOOL WINAPI GetThreadContext(
		  __in     HANDLE hThread,
		  __inout  LPCONTEXT lpContext
		);
*/
	uint32_t eip_save  = popd();
	int h = popd();
	int ctx = popd();
	uint32_t ret = 1;
	CONTEXT context; 

	memset(&context,0x40, sizeof(CONTEXT));
	emu_memory_write_block(mem,ctx,(void*)&context,sizeof(CONTEXT));

	printf("%x\t%s(h=%x)\n", eip_save, ex->fnname, h);
	
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SetThreadContext(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
		BOOL WINAPI SetThreadContext(
		  __in     HANDLE hThread,
		  __inout  LPCONTEXT lpContext
		);
*/
	uint32_t eip_save  = popd();
	int h = popd();
	int ctx = popd();
	uint32_t ret = 1;

	last_set_context_handle = h;
	emu_memory_read_block(mem,ctx,(void*)&last_set_context,sizeof(CONTEXT));

	printf("%x\t%s(h=%x, eip=%x)\n", eip_save, ex->fnname, h, last_set_context.Eip);
	
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ResumeThread(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
		DWORD WINAPI ResumeThread(
		  __in  HANDLE hThread
		);
*/
	uint32_t eip_save  = popd();
	int h = popd();
	uint32_t ret = 0;

	printf("%x\t%s(h=%x)\n", eip_save, ex->fnname, h);
	
	if(/*false*/ h == last_set_context_handle){
		printf("\tTransferring Execution to threadstart %x\n", last_set_context.Eip);
		cpu->reg[eax] = last_set_context.Eax;
		cpu->reg[ebx] = last_set_context.Ebx;
		cpu->reg[ecx] = last_set_context.Ecx;
		cpu->reg[edx] = last_set_context.Edx;
		cpu->reg[esp] = last_set_context.Esp;
		cpu->reg[ebp] = last_set_context.Ebp;
		emu_cpu_eip_set(cpu, last_set_context.Eip);
		return 0;
	}

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_GetMappedFileNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  DWORD WINAPI GetMappedFileName(
		  _In_   HANDLE hProcess,
		  _In_   LPVOID lpv,
		  _Out_  LPTSTR lpFilename,
		  _In_   DWORD nSize
		);
	*/
	uint32_t eip_save = popd();
	uint32_t hproc = popd();
	uint32_t addr = popd();
	uint32_t fname = popd();
	uint32_t size = popd();

	printf("%x\tGetMappedFileNameA(hproc=%x, addr%x)\n", eip_save, hproc, addr);
	
	char *path = "parentdoc.pdf";
    int sz = strlen(path)+1;

	if(size > sz) sz = size;
	if(sz > 0) emu_memory_write_block(mem,fname,path,sz+1);

	set_ret(sz); 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_ZwUnmapViewOfSection(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*  
	ZwUnmapViewOfSection
	*/
	uint32_t eip_save = popd();
	uint32_t h = popd();
	uint32_t addr = popd();

	printf("%x\t%s(h=%x, addr%x)\n", eip_save, ex->fnname, h, addr);

	set_ret(0); //STATUS_SUCCESS
	emu_cpu_eip_set(cpu, eip_save);
	return 0;

}

int32_t	__stdcall hook_strrchr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
		char * strrchr (       char * str, int character );
	*/

	uint32_t eip_save = popd();
	struct emu_string* find = popstring();
	uint32_t it = popd();

	int delta = 0;
	int retval = (int)strrchr(find->data, it);

	if(retval > 0){  //translate char* offset into emu_offset...
		delta = retval - (int)find->data;
		delta += find->emu_offset;
	}

	printf("%x\tstrrchr(%s, 0x%x) = 0x%x\n", eip_save, find->data, it, delta);
	
	emu_string_free(find);
	cpu->reg[eax] = delta;	 
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SetEndOfFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   
/*
	BOOL WINAPI SetEndOfFile(
  _In_  HANDLE hFile
);
*/

	uint32_t eip_save = popd();
	uint32_t hFile = popd();

	uint32_t ret_val = -1;
	uint32_t sizeHigh = 0;

	if( hFile < 5 && opts.h_fopen > 0 )
		ret_val = SetEndOfFile( opts.h_fopen );
	else
		ret_val = SetEndOfFile( (HANDLE)hFile );
		
	printf("%x\tSetEndOfFile(%x) = %x\n", eip_save, hFile, ret_val );
	
	set_ret(ret_val);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_LookupPrivilegeValueA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* BOOL WINAPI LookupPrivilegeValue(
  _In_opt_  LPCTSTR lpSystemName,
  _In_      LPCTSTR lpName,
  _Out_     PLUID lpLuid
); */

	uint32_t eip_save  = popd();
	struct emu_string* sysName = popstring();
	struct emu_string* uName = popstring();
	uint32_t lpLuid = popd();
	uint32_t ret=1;

	printf("%x\tLookupPrivilegeValueA(sysName=%s, name=%s, buf=%x)\n", eip_save, sysName->data, uName->data, lpLuid);
	
	emu_string_free(sysName);
	emu_string_free(uName);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_OpenProcessToken(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* BOOL WINAPI OpenProcessToken(
  _In_   HANDLE ProcessHandle,
  _In_   DWORD DesiredAccess,
  _Out_  PHANDLE TokenHandle
);
); */

	uint32_t eip_save  = popd();
	uint32_t h = popd();
	uint32_t a = popd();
	uint32_t ph = popd();
	uint32_t ret=0xcafebabe;

	printf("%x\tOpenProcessToken(h=%x, access=%x, pTokenHandle=%x) = %x\n", eip_save, h, a, ph, ret);
	
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_EnumProcesses(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* BOOL WINAPI EnumProcesses(
  _Out_  DWORD *pProcessIds,
  _In_   DWORD cb,
  _Out_  DWORD *pBytesReturned
);*/

	uint32_t eip_save  = popd();
	uint32_t pAry = popd();
	uint32_t sz = popd();
	uint32_t pRetSize = popd();
	uint32_t ret=1;

/*	0	    0			
    4	    0	SYSTEM		
  788	    4	SYSTEM	C:\WINDOWS\System32\smss.exe	
  852	  788	SYSTEM	C:\WINDOWS\system32\csrss.exe	
  880	  788	SYSTEM	C:\WINDOWS\system32\winlogon.exe	
  924	  880	SYSTEM	C:\WINDOWS\system32\services.exe	
  936	  880	SYSTEM	C:\WINDOWS\system32\lsass.exe	
 1744	  924	LOCAL SERVICE	C:\WINDOWS\system32\svchost.exe	
 2116	 1872	david	C:\WINDOWS\Explorer.EXE	
 9108	 2116	david	C:\Program Files\Mozilla Firefox\firefox.exe
 */
	uint32_t pids[10] = {0,400,788,852,880,924,936,1744,2116,9108};
	uint32_t max = 10;
	uint32_t retSize = 0;

	if( sz < (max * 4) ) max = sz / 4;
	retSize = max * 4;

	printf("%x\tEnumProcesses(%x, sz=%x, pRet=%x ) ret = %x\n", eip_save, pAry, sz, pRetSize, retSize);
	
	emu_memory_write_block(mem,pAry,&pids[0],retSize);
	emu_memory_write_dword(mem,pRetSize,retSize);

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}



int32_t	__stdcall hook_GetModuleBaseNameA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*DWORD WINAPI GetModuleBaseName(
  _In_      HANDLE hProcess,
  _In_opt_  HMODULE hModule,
  _Out_     LPTSTR lpBaseName,
  _In_      DWORD nSize
);
*/

	uint32_t eip_save  = popd();
	uint32_t h = popd();
	uint32_t hm = popd();
	uint32_t lpstring = popd();
	uint32_t sz = popd();
	uint32_t ret=0;

	char* mName = processNameForPid(h); //handle == pid because of openprocess(pid) = pid
	uint32_t mSz = strlen(mName)+1;

	printf("%x\tGetModuleBaseNameA(h=%x, hMod=%x, buf=%x, sz=%x)\n", eip_save, h, hm, lpstring, sz);
	
	if(sz > mSz){
		emu_memory_write_block(mem,lpstring,mName,mSz);
		ret = mSz;
	}
	 
	free(mName);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_HttpQueryInfoA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*BOOL HttpQueryInfo(
  _In_     HINTERNET hRequest,
  _In_     DWORD dwInfoLevel,
  _Inout_  LPVOID lpvBuffer,
  _Inout_  LPDWORD lpdwBufferLength,
  _Inout_  LPDWORD lpdwIndex
);
*/

	uint32_t eip_save  = popd();
	uint32_t h = popd();
	uint32_t infolevel = popd();
	uint32_t lpstring = popd();
	uint32_t lpsz = popd();
	uint32_t index = popd();
	uint32_t ret=TRUE;
	int handled = 0;

	printf("%x\tHttpQueryInfoA(h=%x, infolevel=%x, buf=%x, lpsz=%x, index=%x)", eip_save, h, infolevel, lpstring, lpsz,index);
	
	if(infolevel==5){
		printf("  (HTTP_QUERY_CONTENT_LENGTH)");
		char* s = "2020";
		emu_memory_write_block(mem,lpstring,s,5);
		emu_memory_write_dword(mem,lpsz,5);
		handled=1;
	}

	if(handled==0){
		emu_memory_write_dword(mem,lpstring,0);
		emu_memory_write_dword(mem,lpsz,0);
	}

	printf("\n");
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_StrToIntA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/*int StrToInt(
  _In_  PCTSTR pszSrc
); */

	uint32_t eip_save  = popd();
	struct emu_string* s = popstring();
	uint32_t ret = s->size > 0 ? atoi(s->data) : 0x0;

	printf("%x\tStrToIntA(%s) = %x\n", eip_save, s->data, ret);
	
	emu_string_free(s);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_gethostbyname(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
struct hostent* FAR gethostbyname(
  _In_  const char *name
);

typedef struct hostent { 16 or 0x10 bytes )
  char FAR      *h_name;       4
  char FAR  FAR **h_aliases;   4
  short         h_addrtype;    2
  short         h_length;      2
  char FAR  FAR **h_addr_list; 4(An array of pointers to IPv4 addresses formatted as a u_long)
} HOSTENT, 

*/

	uint32_t eip_save  = popd();
	struct emu_string* s = popstring();

	uint32_t ret = 0x1000;
	printf("%x\tgethostbyname(%s) = %x\n", eip_save, s->data, ret);

	struct hostent h ;
	
	memset(&h,0,sizeof(hostent));
	h.h_addrtype = AF_INET;
	h.h_addr_list = (char**)0x1020;
	h.h_length = 4;

	uint32_t dummy[4];
	dummy[0] = 0x1014+8;
	dummy[1] = 0;
	dummy[2] = 0x0100007f;
	dummy[3] = 0;

	//if(strcmp(s->data, default_host_name) == 0){
		//strcpy(s->data,"test.com"); /*debug test..JOHN_PC1 == 8*/ }

	if(strcmp(s->data, default_host_name) != 0){
		if(opts.interactive_hooks){
			 printf("\tInteractive mode lookup for: %s ", s->data );
			 struct hostent *remoteHost = gethostbyname(s->data); 
			 struct in_addr addr;
			 uint32_t ip=0;
			 int i=0;
			 if (remoteHost == NULL) {
					printf(" - failed\n");
  			 }else{
					if (remoteHost->h_addrtype == AF_INET) {
						//while (remoteHost->h_addr_list[i] != 0) {
							if(ip==0) ip = *(uint32_t*)remoteHost->h_addr_list[i];
							addr.s_addr = *(u_long *) remoteHost->h_addr_list[i];
							printf(" - address %s (%x)\n", inet_ntoa(addr), addr.s_addr);
							i++;
						//}
					} else /*if (remoteHost->h_addrtype == AF_INET6)*/{
						ip = *(uint32_t*)remoteHost->h_addr_list[0];
						printf(" = address %x\n",ip);
					}
			 }
			 if(ip!=0) dummy[2] = ip;
		}
	}
	 
	 
	emu_memory_write_block(mem, 0x1000, &h, sizeof(hostent));
	emu_memory_write_block(mem, 0x1014, &dummy[0], 4*4);
	
	emu_string_free(s);
	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ZwQueryInformationFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	NTSTATUS ZwQueryInformationFile(
	  _In_   HANDLE FileHandle,
	  _Out_  PIO_STATUS_BLOCK IoStatusBlock,
	  _Out_  PVOID FileInformation,
	  _In_   ULONG Length,
	  _In_   FILE_INFORMATION_CLASS FileInformationClass -> http://msdn.microsoft.com/en-us/library/windows/hardware/ff728840%28v=vs.85%29.aspx
	);

	// 9 = FileNameInformation,
	typedef struct _FILE_NAME_INFORMATION {
	  ULONG FileNameLength;
	  WCHAR FileName[1];
	} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

*/
	int ret = 0; //STATUS_SUCCESS ;
	uint32_t eip_save  = popd();
	uint32_t fHandle   = popd();
	uint32_t iosb      = popd();
	uint32_t finfo     = popd();
	uint32_t length    = popd();
	uint32_t infoClass = popd();
	
	printf("%x\tZwQueryInformationFile(fhand: %x, finfo: %x, len: %x, infoClass: %x ) = %x\n", eip_save, fHandle, finfo, length, infoClass, ret);

	if(infoClass==9 && opts.fopen_fpath != 0){
		int orgLen = strlen(opts.fopen_fpath);
		int wSz = (orgLen+4)*2;
		void* wBuf = SafeMalloc( wSz );
		int lv_Len = MultiByteToWideChar(CP_ACP, 0, opts.fopen_fpath, -1, (LPWSTR)wBuf, wSz);
		if(lv_Len != 0 && finfo != 0 && length >= wSz){
			printf("\tWriting %d bytes to FileNameInformation buffer to emu memory...\n", lv_Len);
			emu_memory_write_dword(mem, finfo, wSz);
			emu_memory_write_block(mem, finfo+4, wBuf, wSz);
		}
		free(wBuf);
	}

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ZwSetInformationProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	NTSTATUS (NTAPI *ZwSetInformationProcess)(
		IN HANDLE hProcess, 
		IN ULONG ProcessInfoClass,    ProcessExecuteFlags = 0x22 (to disable DEP)
		IN PVOID ProcessInfo,         MEM_EXECUTE_OPTION_ENABLE = 2 
		IN ULONG ProcessInfoLength
	);

*/
	int ret = 0; //STATUS_SUCCESS ;
	uint32_t eip_save  = popd();
	uint32_t hProc     = popd();
	uint32_t infoClass = popd();
	uint32_t pArg      = popd();
	uint32_t length    = popd();
	
	uint32_t v=0;
	emu_memory_read_dword(mem,pArg, &v);

	printf("%x\tZwSetInformationProcess(hProc: %x, class: %x, info: %x)   ", eip_save, hProc, infoClass, v);

	if(infoClass=0x22){
		printf(" class=ProcessExecuteFlags");
		if(v==2) printf(" DEP Disabled");
	}

	printf("\n");

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetLocalTime(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	void WINAPI GetLocalTime( _Out_  LPSYSTEMTIME lpSystemTime);
*/
	int ret = 0; 
	uint32_t eip_save  = popd();
	uint32_t pArg      = popd();

	SYSTEMTIME st;
	GetLocalTime(&st);
	 
	emu_memory_write_block(mem,pArg,&st, sizeof(SYSTEMTIME));

	printf("%x\tGetLocalTime(%x)\n", eip_save, pArg);

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ExitWindowsEx(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	BOOL WINAPI ExitWindowsEx( _In_  UINT uFlags, _In_  DWORD dwReason);
*/
	int ret = 0; 
	uint32_t eip_save  = popd();
	uint32_t a1      = popd();
	uint32_t a2      = popd();

	printf("%x\tExitWindowsEx(%x,%x)\n", eip_save, a1,a2);

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SetFileAttributesA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	BOOL WINAPI SetFileAttributes(
  _In_  LPCTSTR lpFileName,
  _In_  DWORD dwFileAttributes
);
*/
	int ret = 0; 
	uint32_t eip_save      = popd();
	struct emu_string* f   = popstring();
	uint32_t a             = popd();

	printf("%x\tSetFileAttributesA(%s,%x)\n", eip_save, f->data ,a);

	set_ret(0);
	emu_string_free(f);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetLastError(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{

	uint32_t eip_save      = popd();
	printf("%x\tGetLastError()\n", eip_save);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_IsDebuggerPresent(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{

	uint32_t eip_save      = popd();
	printf("%x\tIsDebuggerPresent()\n", eip_save);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_ZwQueryInformationProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
	NTSTATUS WINAPI ZwQueryInformationProcess(
	  _In_       HANDLE ProcessHandle,
	  _In_       PROCESSINFOCLASS ProcessInformationClass,
	  _Out_      PVOID ProcessInformation,
	  _In_       ULONG ProcessInformationLength,
	  _Out_opt_  PULONG ReturnLength
);

*/
	int ret = 0; //STATUS_SUCCESS ;
	uint32_t eip_save  = popd();
	uint32_t hProc     = popd();
	uint32_t infoClass = popd();
	uint32_t pArg      = popd();
	uint32_t length    = popd();
	uint32_t out_length= popd();
	
	uint32_t v=0;
	emu_memory_read_dword(mem,pArg, &v);

	char *name = "Unknown"; //0 Retrieves a pointer to a PEB structure that can be used to determine whether the specified process is being debugged
    //ProcessDebugPort 7  Retrieves a DWORD_PTR value that is the port number of the debugger for the process. A nonzero value indicates that the process is being run under the control of a ring 3 debugger.
    //ProcessWow64Information 26 is running in the WOW64?  
	//ProcessImageFileName 27 Retrieves a UNICODE_STRING value containing the name of the image file for the process.

	if(infoClass==0) name = "ProcessBasicInformation";
	if(infoClass==7) name = "ProcessDebugPort";
	if(infoClass==26) name = "ProcessWow64Information";
	if(infoClass==27) name = "ProcessImageFileName";
	
	printf("%x\tZwQueryInformationProcess(hProc: %x, class: %x (%s), info: %x)   ", eip_save, hProc, infoClass, name, pArg);
	
	if(infoClass==7) {
		emu_memory_write_dword(mem,pArg,0);
		ret = 0;
	}

	printf("\n");

	cpu->reg[eax] = ret;
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_OpenFileMappingA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*
	HANDLE WINAPI OpenFileMapping(
	  _In_  DWORD dwDesiredAccess,
	  _In_  BOOL bInheritHandle,
	  _In_  LPCTSTR lpName
	);
	*/
	uint32_t eip_save = popd();
	uint32_t access = popd();
	uint32_t inherit = popd();
	struct emu_string* lpName = popstring();
	uint32_t rv = 0;
	uint32_t hFile = 0;

	/*if(opts.interactive_hooks == 1){
		
		if(opts.fopen_fpath == NULL){
			printf("\tYou can use /fopen <file> to do interactive mode for OpenFileMapping\n");
		}else{
			//handle from GetFileSizeScanner...We need a specific type of handle for this though
			//hFile = (uint32_t)CreateFile(opts.fopen_fpath, GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); 
			//if( hFile == -1 ) hFile = (uint32_t)opts.h_fopen; 
		}
		 
		//rv = (uint32_t)OpenFileMapping();
	} */
	
	printf("%x\tOpenFileMappingA(%x, %s) = %x\n", eip_save,access, emu_string_char(lpName),rv);

	emu_string_free(lpName);
	set_ret(rv);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_time(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	//cdecl msvcrt.time
	uint32_t eip_save = popd();
	uint32_t pTime = get_arg(0);

	time_t now;
	uint32_t ret = time(&now);

	printf("%x\ttime(%x)\n", eip_save, pTime);
	if(pTime!=0) emu_memory_write_block(mem,pTime,&now,sizeof(time_t));

	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_srand(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	//cdecl msvcrt. void srand (unsigned int seed);
	uint32_t eip_save = popd();
	uint32_t seed = get_arg(0);

	printf("%x\t%s(%x)\n", eip_save, ex->fnname ,seed);
	srand(seed);

	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_rand(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	//cdecl msvcrt. void srand (unsigned int seed);
	uint32_t eip_save = popd();
	uint32_t ret = rand();

	printf("%x\t%s() = %x\n", eip_save, ex->fnname ,ret);
	
	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_inet_addr(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*unsigned long inet_addr(_In_  const char *cp); does dns lookup and returns ip */

	uint32_t eip_save = popd();
	struct emu_string* lpName = popstring();

	uint32_t ret = inet_addr("127.0.0.1");

	printf("%x\t%s(%s) = ", eip_save, ex->fnname, lpName->data );
	
	if(opts.interactive_hooks){
		ret = inet_addr(lpName->data);
		printf(" = %x\n", ret);
	}else{
		printf(" (Use interactive hooks to lookup real ip, using localhost)\n");
	}

	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_wsprintfA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		int __cdecl wsprintf(
		  _Out_  LPTSTR lpOut,
		  _In_   LPCTSTR lpFmt,
		  _In_    ...
		);
	*/
	uint32_t eip_save = popd();
	uint32_t lpOut = get_arg(0);
	uint32_t lpFmt = get_arg(4);
	
	struct emu_string *fmat = emu_string_new();
	emu_memory_read_string(mem, lpFmt, fmat, 1256);

	printf("%x\t%s(buf=%x, fmat=%s",eip_save, ex->fnname, lpOut, fmat->data);

	int sz = getFormatParameterCount(fmat); 
	if(sz > 0) printf(" args(%x)=[",sz);

	int params[10];
	if(sz > 10) sz = 10;
	
	for(int i=0; i < sz; i++){
		params[i] = get_arg(8+(i*4));
		printf("%x" , params[i]);
		if(i+1 != sz) printf(","); else printf("] ");
	}

	printf(")\n");

	char ret[150];
	sz = sprintf(ret,"wsprintfA_%x", eip_save);
	emu_memory_write_block(mem,lpOut, ret, sz+1);
	set_ret(sz); 

    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(fmat);
	return 0;
}

int32_t	__stdcall hook_RtlDecompressBuffer(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	typedef DWORD ( _stdcall *RtlDecompressBuffer )(
	                    IN ULONG    CompressionFormat,
	                    OUT PVOID   DestinationBuffer,
	                    IN ULONG    DestinationBufferLength,
	                    IN PVOID    SourceBuffer,
	                    IN ULONG    SourceBufferLength,
	                    OUT PULONG  pDestinationSize );

    RtlDecompressBuffer fRtlDecompressBuffer;
	uint32_t ret = 0; //STATUS_SUCCESS
	
	uint32_t eip_save = popd();
	uint32_t fmat = popd();
	uint32_t ubuf = popd();
	uint32_t usz = popd();
	uint32_t cbuf = popd();
	uint32_t csz = popd();
	uint32_t fsz = popd();

	printf("%x\t%s(fmat=%x,ubuf=%x, usz=%x, cbuf=%x, csz=%x) ", eip_save, ex->fnname, fmat, ubuf, usz,cbuf, csz );
	
	if(opts.interactive_hooks){
		uint32_t szOut=0;
		void *rUbuf = SafeMalloc(usz);
		void *rCBuf = SafeMalloc(csz);
		emu_memory_read_block(mem,cbuf,rCBuf,csz);
		fRtlDecompressBuffer = (RtlDecompressBuffer) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlDecompressBuffer" );
		if((int)fRtlDecompressBuffer==0){
			printf("GetProcAddress Failed Skipping...\n");
		}else{
			ret = (*fRtlDecompressBuffer)(fmat,rUbuf,usz,rCBuf,csz, &szOut);   
			if(szOut>0){
				printf("(Outsz: %x)",szOut);
				emu_memory_write_block(mem,ubuf,rUbuf,szOut);
			}
			emu_memory_write_dword(mem,fsz,szOut);
			printf(" = %x\n", ret);
		}
		free(rUbuf);
		free(rCBuf);
	}else{
		printf(" (supports -i)\n");
	}

	set_ret(ret);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_RtlZeroMemory(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/*VOID RtlZeroMemory(
	  _Out_  VOID UNALIGNED *Destination,
	  _In_   SIZE_T Length
	);*/

	uint32_t eip_save = popd();
	uint32_t dest = popd();
	uint32_t leng = popd();

	printf("%x\t%s(0x%x,0x%x)\n", eip_save, ex->fnname, dest, leng );
	
	if(opts.show_hexdumps){
		char* tmp = SafeMalloc(leng);
		emu_memory_read_block(mem,dest,tmp,leng);
		start_color(colors::myellow);
		printf("\tShellcode is about to zero the current memory:\n");
		end_color();
		hexdump((unsigned char*)tmp,leng);
		free(tmp);
	}

	for(uint32_t i=0; i< leng; i++){
		emu_memory_write_byte(mem,dest+i,0);
	}

	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_swprintf(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		int __cdecl swprintf ( wchar_t * ws, size_t len, const wchar_t * format, ... );
	*/
	uint32_t eip_save = popd();
	uint32_t lpOut = get_arg(0);
    uint32_t leng = get_arg(4);
	uint32_t lpFmt = get_arg(8);
	
	struct emu_string *fmat = emu_string_new();
	emu_memory_read_wide_string(mem, lpFmt, fmat, 1256);

	printf("%x\t%s(buf=%x, fmat=%s",eip_save, ex->fnname, lpOut, fmat->data);

	int sz = getFormatParameterCount(fmat); 
	if(sz > 0) printf(" args(%x)=[",sz);

	int params[10];
	if(sz > 10) sz = 10;
	
	for(int i=0; i < sz; i++){
		params[i] = get_arg(8+(i*4));
		printf("%x" , params[i]);
		if(i+1 != sz) printf(","); else printf("] ");
	}

	printf(")\n");

	char ret[150];
	sz = sprintf(ret,"swprintf_%x", eip_save);
	emu_memory_write_block(mem,lpOut, ret, sz+1);
	emu_memory_write_dword(mem,lpOut+sz+1,0);
	set_ret(sz); 

    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(fmat);
	return 0;
}

int32_t	__stdcall hook_RtlDosPathNameToNtPathName_U(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		extern (Windows) static bool RtlDosPathNameToNtPathName_U(
			in const(wchar)* DosPathName, 
			out UnicodeString NtPathName,
			out const(wchar)* NtFileNamePart, 
			out CurDir DirectoryInfo);

			UnicodeString{ length - 4, sPtr - 4 }
	*/

	uint32_t eip_save = popd();
	struct emu_string* path = popwstring();
	uint32_t a = popd();
	uint32_t b = popd();
	uint32_t c  = popd();
	
	printf("%x\t%s(%s, %x,%x,%x)\n",eip_save, ex->fnname, path->data,a,b,c);

	set_ret(1); 
    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(path);
	return 0;
}

int32_t	__stdcall hook_ZwOpenFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		NTSTATUS ZwOpenFile(
		  _Out_  PHANDLE FileHandle,
		  _In_   ACCESS_MASK DesiredAccess,
		  _In_   POBJECT_ATTRIBUTES ObjectAttributes,
		  _Out_  PIO_STATUS_BLOCK IoStatusBlock,
		  _In_   ULONG ShareAccess,
		  _In_   ULONG OpenOptions
		);

	*/

	uint32_t eip_save = popd();
	uint32_t a = popd();
	uint32_t b = popd();
	uint32_t c  = popd();
	uint32_t d  = popd();
	uint32_t e  = popd();
	uint32_t f  = popd();

	printf("%x\t%s(%x,%x,%x,%x,%x,%x)\n",eip_save, ex->fnname, a,b,c,d,e,f);

	set_ret(1); 
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_MoveFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		BOOL WINAPI MoveFile(
		  _In_  LPCTSTR lpExistingFileName,
		  _In_  LPCTSTR lpNewFileName
		);

	*/

	uint32_t eip_save = popd();
	struct emu_string* path = isWapi(ex->fnname) ?  popwstring() : popstring();
	struct emu_string* path_new = isWapi(ex->fnname) ?  popwstring() : popstring();
	
	
	printf("%x\t%s(%s, %s)\n",eip_save, ex->fnname, path->data, path_new->data);

	set_ret(1); 
    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(path);
	emu_string_free(path_new);
	return 0;
}



int32_t	__stdcall hook_gethostname(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		int gethostname(
		  _Out_  char *name,
		  _In_   int namelen
		);
	*/

	uint32_t eip_save = popd();
	uint32_t lpName = popd();
	uint32_t sz = popd();
	uint32_t copySz = 0;
	
	printf("%x\t%s(%x, %x) = %s\n",eip_save, ex->fnname, lpName, sz, default_host_name);
	
	copySz = strlen(default_host_name);
	if(copySz > sz) copySz = sz-1;
	emu_memory_write_block(mem,lpName,default_host_name,copySz+1);

	set_ret(0); //Success 
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_SendARP(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
	    test me more sometime...

		DWORD SendARP(
		  _In_     IPAddr DestIP,
		  _In_     IPAddr SrcIP,
		  _Out_    PULONG pMacAddr,
		  _Inout_  PULONG PhyAddrLen
		);
	*/

	uint32_t eip_save = popd();
	uint32_t destIP = popd();
	uint32_t srcIP = popd();
	uint32_t pMacAddr = popd();
	uint32_t PhyAddrLen = popd();
	
	uint32_t copySz = 0;
	uint32_t sz = 0;
    char *defaultMAC = "DE-AD-BE-EF-S4-17";

	in_addr ia;
	char dst[20];
	char src[20];
	memset(dst,0,20);
	memset(src,0,20);

	memcpy(&ia,&destIP,4);
	char* tmp = inet_ntoa(ia);
	if(tmp!=0) strncpy(dst,tmp, 20);

	memcpy(&ia,&srcIP,4);
	tmp = inet_ntoa(ia);
	if(tmp!=0) strncpy(src,tmp, 20);

	emu_memory_read_dword(mem,PhyAddrLen, &sz);

	printf("%x\t%s(%s, %s, %x, %x) = %s\n",eip_save, ex->fnname, dst,src,pMacAddr,sz, defaultMAC );
	
	copySz = strlen(defaultMAC);
	if(copySz > sz) copySz = sz-1;
	emu_memory_write_block(mem,pMacAddr,defaultMAC,copySz+1);
	emu_memory_write_dword(mem,PhyAddrLen,copySz+1);

	set_ret((uint32_t)NO_ERROR);  
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_PathFileExists(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	/* 	
		BOOL PathFileExists(
		  _In_  LPCTSTR pszPath
		);
	*/

	uint32_t eip_save = popd();
	struct emu_string* path = isWapi(ex->fnname) ?  popwstring() : popstring();	
	
	printf("%x\t%s(%s)\n", eip_save, ex->fnname, path->data);

	set_ret(FALSE); 
    emu_cpu_eip_set(cpu, eip_save);
	emu_string_free(path);
	return 0;
}






int SysCall_Handler(int callNumber, struct emu_cpu *c){
	
	uint32_t service = c->reg[eax]; 
	char* name = emu_env_w32_getSyscall_service_name(service);
	if(name == NULL) name = "Unknown?";

	printf("%x\tSysCall(Service: 0x%04x, Name: %s)\n", c->eip, service , name );

	return -1; //unhandled will break
	

}