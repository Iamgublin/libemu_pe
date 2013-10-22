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

/*  this source has been modified from original see changelog 

	I am not going to really impement Wchar api..if they call MultiByte2Wc, i am just returning
	the ascii string, cause they are just going to send it to hooks latter on. So fake it and
	use the A hooks for the W api. works out unless they were natively working in Wchar which
	I have yet to see. its a dirty hack, but in practice its working just fine...

	TODO: 
		  - implement a break on memory access command using mem monitor? maybe overkill for shellcode...
		  - CreateFileMapping/MapViewofFile - figure out how to make work...
		  - add string deref for pointers in stack dump, deref regs and dword dump?
		  - log call stack similar to eip log ?
*/


#include <stdlib.h>
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
#include "stdint.h"

extern "C"{
	#include "emu_hashtable.h"
}

#define INT32_MAX 0x7fffffff
#define F(x) (1 << (x))
#define CPU_FLAG_ISSET(cpu_p, fl) ((cpu_p)->eflags & (1 << (fl)))
#define FLAG(fl) (1 << (fl))

#include "options.h"
#include <io.h>
#include <signal.h>
#include <windows.h>
#include <conio.h>

#pragma warning(disable: 4311)

struct hh{
	uint32_t eip;
	uint32_t addr;
	char *name;
};

struct emm_mode{
	struct hh hooks[11];
	struct hh bps[11];
	struct hh patches[11];
};

struct m_allocs{
	uint32_t base;
	uint32_t size;
};

struct result{
	uint32_t final_eip;
	uint32_t offset;
	int steps;
	int org_i;
	int parse_error;
	int step_error;
	int foundExport;
	uint32_t eip_log[10];
	int overLimit;
	int inDllMemory;
};

struct signature{
	char* name;
	char* sig;
	int   siglen;
};

int malloc_cnt=0;
struct m_allocs mallocs[21];

struct emm_mode emm; //extended memory monitor
struct run_time_options opts;
struct emu *e = 0;           //one global object 
struct emu_cpu *cpu = 0;
struct emu_memory *mem = 0;
struct emu_env *env = 0;
	
void debugCPU(struct emu *e, bool showdisasm);
void disasm_block(int offset, int size);
int fulllookupAddress(int eip, char* buf255);
int file_length(FILE* fp);
void init_emu(void);
int disasm_addr_simple(int);
void LoadPatch(char* fpath);
void loadraw_patch(uint32_t base, char* fpath);
void HandleDirMode(char* folder);
void nl(void);
bool isDllMemAddress(uint32_t eip);
extern char* SafeMalloc(int size);
extern uint32_t popd(void);
extern int SysCall_Handler(int callNumber, struct emu_cpu *c);

uint32_t FS_SEGMENT_DEFAULT_OFFSET = 0x7ffdf000;

int ctrl_c_count=0;
uint32_t last_good_eip=0;
uint32_t previous_eip=0;
bool disable_mm_logging = false;
int lastExceptionHandler=0;
int exception_count=0;
bool in_repeat = false;
int mdll_last_read_eip=0;
int mdll_last_read_addr=0;
uint32_t eip_log[10] = {0,0,0,0,0,0,0,0,0,0};
const uint32_t eip_log_sz = 10;

bool hexdump_color = false;
DWORD orgt;
HANDLE hCon = 0;
HANDLE hConOut = 0;

//overview stats variables
bool ov_reads_dll_mem = false;
bool ov_writes_dll_mem = false;
bool ov_ininit_list = false;
bool ov_inmem_list = false;
bool ov_inload_list = false;
bool ov_basedll_name = false;
uint32_t ov_decode_self_addr[11] = {0,0,0,0,0,0,0,0,0,0,0};

extern uint32_t next_alloc;

//enum Color { DARKBLUE = 1, DARKGREEN=2, DARKTEAL=3, DARKRED=4, 
//			   DARKPINK=5, DARKYELLOW=6, GRAY=7, DARKGRAY=8, 
//             BLUE=9, GREEN=10, TEAL=11, RED=12, PINK=13, YELLOW=14, WHITE=15 };

enum colors{ mwhite=15, mgreen=10, mred=12, myellow=14, mblue=9, mpurple=5, mgrey=7, mdkgrey=8 };

void end_color(void){
	if(opts.no_color) return;
	//printf("\033[0m"); 
	SetConsoleTextAttribute(hConOut,7); 
}
void nl(void){ printf("\n"); }
void restore_terminal(int arg)    { SetConsoleMode(hCon, orgt); }
void atexit_restore_terminal(void){ SetConsoleMode(hCon, orgt); }

void start_color(enum colors c){
	//char* cc[] = {"\033[37;1m", "\033[32;1m", "\033[31;1m", "\033[33;1m", "\033[34;1m", "\033[35;1m"};
	if(opts.no_color) return;
	//printf("%s", cc[c]);
    SetConsoleTextAttribute(hConOut, c);
}

//            0      1      2      3      4      5         6      7  
int regs[] = {0,    0,      0,     0,  0x12fe00,0x12fff0  ,0,    0};
char *regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

//http://en.wikipedia.org/wiki/FLAGS_register_(computing)
	                    /* 0     1     2     3      4       5       6     7 */
/*const char *eflagm[] = { "CF", ""  , "PF", ""   , "AF"  , ""    , "ZF", "SF", 
	                     "TF", "IF", "DF", "OF" , "IOPL", "IOPL", "NT", "",
	                     "RF", "VM", "AC", "VIF", "RIP" , "ID"  , "", "",
	                     "",   "",   "",   "",    "",     "",     "", ""};
*/

extern const char *eflagm[];

struct mmm_point mm_points[] = 
{ //http://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	{0x00251ea0,"PEB Data",0},
	{0x7ffdf000,"SEH (fs0)",0},
	{0x7ffdf030,"*PEB (fs30)",0},
	{0x7ffdf000+4,"Top of thread Stack (fs4)",0},
	{0x7ffdf000+0x18,"TEB (fs18)",0},
	{0x251ea0+0xC,"peb.InLoadOrderModuleList",0},
	{0x251ea0+0x14,"peb.InMemoryOrderModuleList",0},
	{0x251ea0+0x1C,"peb.InInitializationOrderModuleList",0},
	{0x252ea0+0x00,"ldrDataEntry.InLoadOrderLinks",0}, /* only addresses here for the [0] entry rest would spam */
	{0x252ea0+0x08,"ldrDataEntry.InMemoryOrderLinks",0},
	{0x252ea0+0x10,"ldrDataEntry.InInitializationOrderLinks",0},
	{0x00253320,   "ldrDataEntry.BaseDllName",0},
	{0x7c862e62,   "UnhandledExceptionFilter",0},
	{0x7c80ada9,   "GetProcAddress Signature Scanner",0},
	{0,NULL,0},
};

//each dll gets two entries. (yes this sucked to generate)
//first is imagebase + sizeof(pe headers) (roughly) - start of export table
//second is image base + rva export table + export table size - through base + size of image
//even then these had to be tuned a little..luckily stray output tells us which to refine...
struct mmm_range mm_ranges[] = 
{ 
	{0, "kernel32", 0x7c800300, 0x7C80260f},                        
	{0, "kernel32", 0x7c800000+0x261C+0x6C7B+0x1, 0x7C800000+0x831e9},  

    {1, "ws2_32",   0x71AB0300, 0x71aB1400},  
	{1, "ws2_32",   0x71AB0000+0x1404+0x11ed+0x1, 0x71aB0000+0x16DC8},  

	{2, "user32",   0x7e410300, 0x7e4138ff},                        
	{2, "user32",   0x7e410000+0x3900+0x4BA9+0x1, 0x7e410000+0x90DE4},  

	{3, "shell32",  0x7c9c0300, 0x7c9e7d4f},
	{3, "shell32",  0x7c9c0000+0x27D50+0x2918+0x1, 0x7c9c0000+0x8164FC},

	{4, "msvcrt",   0x77c10300, 0x77c10000+0x489F0-2},
	{4, "msvcrt",   0x77c10000+0x489F0+0x4326+0x1, 0x77c10000+0x58000},

	{5, "urlmon",   0x78130300, 0x78130000+0x1d8c-2},
	{5, "urlmon",   0x78130000+0x1d8c+0x10cd+0x1, 0x78130000+0x128000},
	
	{6, "wininet",  0x3d930300, 0x3d93183f},
	{6, "wininet",  0x3d930000+0x1844+0x1D4A+0x1, 0x3d930000+0xD074f},

	{7, "ntdll",    0x7c900300, 0x7c9033ff},
	{7, "ntdll",    0x7C900000+0x3400+0x9A5F+1, 0x7c900000+0xB1EB8},  

	{8, "advapi",    0x77DD0300, 0x77DD0000+0x16A4-2},
	{8, "advapi",    0x77DD0000+0x16A4+0x5252+1, 0x77DD0000+0x710B},  

	{9, "shlwapi",    0x77F60000+0x300, 0x77F60000+0x1820-2},
	{9, "shlwapi",    0x77F60000+0x1820+0x027FE+1, 0x77F60000+0x76000},  

	{10, "shdocvw",    0x7E290000+0x300, 0x7E290000+0x14480-2},
	{10, "shdocvw",    0x7E290000+0x14480+0x04E0+1, 0x7E290000+0x170084},  

	{0, NULL, 0,0},
};

struct signature signatures[] = 
{ 
	{"encoder.msf.fnstenv_mov",			"\xD9\xEE\xD9\x74\x24\xF4\x5B\x81\x73\x13", 10 },
	{"encoder.msf.jmp_call_additive",	"\xEB\x0C\x5E\x56\x31\x1E\xAD\x01\xC3",		9 },
	{"encoder.msf.noupper",				"\xEB\x19\x5E\x8B\xFE\x83\xC7\x00\x8B\xD7", 10 },
	{"encoder.msf.shikata_ga_nai",		"\xDA\xD7\x29\xC9\xB1\x5A\xD9\x74\x24\xF4", 10 },
	{"encoder.msf.single_static_bit",	"\xEB\x65\x5E\x31\xED\x83\xE1\x01\x83\xE3\x01", 11 },
	{"encoder.msf.countdown",			"\xFF\xC1\x5E\x30\x4C\x0E\x07\xE2\xFA", 9 },
	{"encoder.msf.call4_dw",			"\xFF\xC0\x5E\x81\x76\x0E", 6 },
	{"encoder.77efe4.xor",				"\x30\x45\x00\x45\x49\x75\xF9\xEB\x00", 9 },
	{"hasher.ror7.ebx", 			    "\x3A\xD6\x74\x08\xC1\xCB\x07\x03\xDA\x40", 10 }, /*ror7.bycount contains this..*/
	{"hasher.rorD.edx",                 "\xAC\x84\xC0\x74\x07\xC1\xCA\x0D\x01\xC2\xEB\xF4", 12},
	{"hasher.rorD.edi.msf",             "\x33\xC0\xAC\x3A\xC4\x74\x07\xC1\xCF\x0D\x03\xF8\xEB\xF2", 14},
	{"hasher.rorD.ebx.bycount",         "\x0F\xBE\x10\x3A\xD6\x74\x08\xC1\xCB\x0D\x03\xDA\x40\xEB\xF1", 15},
	{"hasher.ror7.ebx.bycount",         "\x0F\xBE\x10\x3A\xD6\x74\x08\xC1\xCB\x07\x03\xDA\x40\xEB\xF1", 15},
	{"hasher.rol3xor",					"\xC1\xC2\x03\x32\x10\x40\x80\x38\x00\x75\xF5", 11 },
	{"hasher.ror12",                    "\xAC\x84\xC0\x74\x07\xC1\xCF\x12\x01\xC7\xEB\xF4", 12},
	{"hasher.harmony",					"\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10", 23 },
	{"template.hll.didier",				"\x89\x45\xF8\x68\xFA\x8B\x34\x00\x68\x88\x4E\x0D\x00\xE8\x08\x00\x00\x00\x89\x45\xFC", 21 },
	{"template.hll.didier.orshl.hasher","\x8A\x10\x80\xCA\x60\x03\xDA\xD1\xE3\x03\x45\x10\x8A\x08\x84\xC9\xE0\xEE", 18 },
	{"template.hll.wishmaster",		    "\x57\x8B\x6C\x24\x18\x8B\x45\x3C\xFF\x74\x05\x78\xFF\x74\x05\x7C\x8B\x54\x05\x78\x03\xD5\x8B\x4A\x18\x8B\x5A\x20", 28 },
	{"generic.hll.prolog.1",			"\x55\x8B\xEC\x81\xEC", 5 },
	{"generic.hll.prolog.2",			"\x55\x89\xE5\x81\xEC", 5 },
	{"generic.hll.prolog.3",			"\x55\x8B\xEC\x83\xC4", 5 },
	{"peb.k32Base.ru",                  "\x64\x8B\x71\x30\x8B\x76\x0C\x8B\x76\x1C\x8B\x5E\x08\x8B\x56\x20\x8B\x36\x66\x39\x4A\x18", 22 },
	{"scanner.GetProcAddress",          "\x56\xAC\x3C\x8B\x75\xFB\x80\x3E\x7D\x75\xF6\x83\xC6\x03\xAD\x3D\xFF\xFF\x00\x00\x75\xEB\x83\xEE\x11", 25},
	{"scanner.hookcheck",               "\x80\x38\xE8\x74\x0A\x80\x38\xE9\x74\x05\x80\x38\xEB\x75\x11", 15},
    {"hasher.strcmp",                   "\x57\x51\x52\x56\x8b\x36\x03\x75\xfc\xfc\xf3\xa6", 12},
    {"macro.jmp+5",                     "\x83\xC2\x05\x8B\xFF\x55\x8B\xEC\xFF\xE2", 10},
	{"rop.msvcrt.7.0.2600.5512.VirtAlloc",     "\x9A\x4D\xC3\x77\xCC\xAA\xC2\x77\x16\x1D\xC2\x77\x20\x11\xC1\x77\xF9\x2D\xC1\x77\x24\x55\xC3\x77", 24},
	{"rop.msvcrt.7.0.2600.5512.VirtAlloc2",    "\xD1\xC1\xC4\x77\xCC\xAA\xC2\x77\x92\xE3\xC4\x77\x0C\x11\xC1\x77\xF9\x2D\xC1\x77\xB4\x54\xC3\x77", 24},
	{"rop.advapi32.5.1.2600.5755.ZwSetInformationProcess", "\x1F\x5C\xE2\x77\x04\x14\xDD\x77\x48\xD4\xDF\x77\xFF\xFF\xFF\xFF\x5F\x8A\xE1\x77", 20},
	{"rop.icucnv36.PDF.MapViewOfFile",         "\x29\x6F\x80\x4A\x00\x00\x8A\x4A\x96\x21\x80\x4A\x90\x1F\x80\x4A\x29\x6F\x80\x4A\xEF\x6C\x80\x4A", 24},
	{"rop.msvcr71.Java.WhitePhosphorus",       "\x49\xD7\x34\x7C\xAA\x58\x34\x7C\xFA\x39\x34\x7C\xC0\xFF\xFF\xFF\xB1\x1E\x35\x7C\x48\x46\x35\x7C\xEA\x30\x35\x7C\xC1\x4C\x34\x7C",32},
	{"rop.msvcr71.Java.VirtualProtect",        "\x97\x7F\x34\x7C\x51\xA1\x37\x7C\x81\x8C\x37\x7C\x30\x5C\x34\x7C",16},
	{"rop.mfc71u.v7.10.3077.0.VirtualProtect", "\x0C\x9E\x25\x7C\xF0\x12\x25\x7C\xBC\xE7\x2F\x7C\x14\xF0\x26\x7C\x09\x08\x2C\x7C\x89\x99\x28\x7C\x0C\x9E\x25\x7C\x01\xB0\x32\x7C",32},
	{"rop.msvcr70.v7.00.9466.0.VirtualProtect","\x3F\x06\x03\x7C\xA1\x58\x03\x7C\xFD\x90\x03\x7C\x4F\x3A\x02\x7C\xA1\x58\x03\x7C\x94\x5E\xFF\x83\xCD\x67\x01\x7C\xB7\x26\x01\x7C",32},
	{"rop.cryptocme2.PDF.abysssec",            "\xAF\x90\x00\x10\xF8\x0B\x0C\x0C\xEA\x0F\x01\x10\x87\xCD\x09\x10",16},
	{NULL, NULL, 0},
};


bool isInteractive(char* api){
	char* iApi[] = {"MapViewOfFile","SetFilePointer","ReadFile","fclose","fopen","fwrite","_lcreat",
				    "_lclose","_lwrite","_hwrite","CloseHandle","CreateFileA","WaitForSingleObject",
					"WriteFile","accept","bind","closesocket","connect","listen","recv","send",
					"sendto","socket","WSASocketA","CreateFileMappingA","FindFirstFileA",
					"fread","ExpandEnvironmentStringsA","lstrlenA","lstrcmpiA","lstrcatA","strcat",
					"RtlDecompressBuffer", NULL };

	int i=0;
	while( iApi[i] != NULL ){
		if(strcmp(api, iApi[i])==0 ){
			return true;
		}
		i++;
	}
	return false;
}

bool isProxied(char* api){
	char* iApi[] = {"CryptReleaseContext","CryptDestroyHash","CryptGetHashParam","CryptHashData",
					"CryptCreateHash","CryptAcquireContextA","CryptAcquireContextW","GetCommandLineA","GetSystemTime",
					"GetTempPathA","GetTempFileNameA","strstr","SHGetFolderPathA","SHGetSpecialFolderPathA",
					"ExpandEnvironmentStringsA","lstrlenA","lstrcmpiA","lstrcatA","strcat",
					"RtlDecompressBuffer",NULL };

	int i=0;
	while( iApi[i] != NULL ){
		if(strcmp(api, iApi[i])==0 ){
			return true;
		}
		i++;
	}
	return false;
}

void showEipLog(void){
	nl();
	for(int i=0;i < eip_log_sz;i++){
		if(eip_log[i] == 0) break; 
		disasm_addr_simple(eip_log[i]);
	}
}

void logEip(uint32_t eip){
	
	for(int i=0;i < eip_log_sz;i++){
		if(eip_log[i] == 0){  //initial fill
			eip_log[i] = eip;
			return;
		} 
	}

	for(int i=1;i < eip_log_sz;i++){
		eip_log[i-1] = eip_log[i];
	}

	eip_log[ eip_log_sz-1 ] = eip;
}



char* FileNameFromPath(char* path){
	if(path==NULL || strlen(path)==0) return strdup("");
	unsigned int x = strlen(path);
	while(x > 0){
		if( path[x-1] == '\\') break;
		x--;
	}
	int sz = strlen(path) - x;
	char* tmp = (char*)malloc(sz+2);
	memset(tmp,0,sz+2);
	for(int i=0; i < sz; i++){
		tmp[i] = path[x+i];
	}
	return tmp;
}

char* GetParentFolder(char* path){
	if(path==NULL || strlen(path)==0) return strdup("");
	unsigned int x = strlen(path);
	while(x > 0){
		if( path[x-1] == '\\') break;
		x--;
	}
	char* tmp = strdup(path);
	tmp[x]=0;
	return tmp;
}

bool FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);
  bool rv = (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) ? true : false;
  return rv;
}

bool FolderExists(char* folder)
{
	DWORD rv = GetFileAttributes(folder);
	if( rv == INVALID_FILE_ATTRIBUTES) return false;
	if( !(rv & FILE_ATTRIBUTE_DIRECTORY) ) return false;
	return true;
}

int bInstr(char *buf, char *match, int bufLen, int matchLen){

	int i, j;

	for(i=0; i < bufLen ; i++){
		
		if(buf[i] == match[0]){
			for(j=1; j < matchLen; j++){
				if(buf[i+j] != match[j]) break;
			}
			if(j==matchLen) return i;
		}

	}

	return -1;
}

void showSigs(void){
	int i=0; 
	int size=0;
	bool doDisasm = false;

	char* tmp = GetCommandLineA(); //this is called in parse_opts before all switches processed...
	if(strstr(tmp,"disasm") > 0){
		init_emu();
		doDisasm = true;
	}

	printf("\n Signatures: \n");
	while( signatures[i].siglen > 0 ){
		printf("\t%s\r\n",signatures[i].name);
		if(doDisasm){
			if(strstr(signatures[i].name,"rop.") == NULL){
				emu_memory_write_block(mem,0x401000, signatures[i].sig, signatures[i].siglen);
				emu_memory_write_dword(mem, 0x401000+signatures[i].siglen, 0);
				emu_memory_write_dword(mem, 0x401000+signatures[i].siglen+4, 0);
				while(size < signatures[i].siglen){
					printf("\t\t");
					size += disasm_addr_simple( 0x401000+size );
				}
				nl();
			}else{
				//display as dwords cant disasm
				start_color(colors::mgreen);
				while(size < signatures[i].siglen){
					uint32_t v;
					memcpy(&v,signatures[i].sig+size, 4);
					printf("\t\t%x\n",v);
					size += 4;
				}
				end_color();
				nl();
			}
		}
		i++;
		size=0;
	}
	printf("\n Total %d\n", i);
}	
	
int sigScan(uint32_t baseAddress, uint32_t size){

	int i=0; 
	int match_at = -1;
	int matches = 0;
	char* tmp = (char*)malloc(size);
	emu_memory_read_block(mem, baseAddress, tmp, size);
	
	while( signatures[i].siglen > 0 ){
		match_at = bInstr( tmp, signatures[i].sig, size, signatures[i].siglen - 1);
		if(match_at >= 0){
			if(matches==0) nl();
			matches++;
			printf("\t%x \t %s \n", baseAddress + match_at, signatures[i].name); 
		}
		i++;
	}

	free(tmp);
	return matches;
}

void sigChecks(void){
	printf("\nSignatures Found: ");
	int x = sigScan( opts.baseAddress, opts.size);
	if( malloc_cnt > 0 ){ //then there were allocs made..		
		for(int i=0; i < malloc_cnt; i++){
			x += sigScan( mallocs[i].base, mallocs[i].size);
		}
	}
	if(x==0) printf(" None\n");
}

int __stdcall ctrl_c_handler(DWORD arg){
	if(arg==0){ //ctrl_c event
			opts.verbose = 3;             //break next instruction
			ctrl_c_count++;               //user hit ctrl c a couple times, 
			if(ctrl_c_count > 1) exit(0); //must want out for real.. (zeroed each step)
			return TRUE;
	}
	return FALSE;
}

void add_malloc(uint32_t base, uint32_t size){
	if( malloc_cnt > 20 ) return;
	if(opts.report) emu_memory_add_monitor_range(0x66, base, base + size); //catch instructions which write to it
	mallocs[malloc_cnt].base = base;
	mallocs[malloc_cnt].size = size;
	malloc_cnt++;
}

void mm_hook(uint32_t address){ //memory monitor callback function

	int i=0;
	//printf("in mm_hook addr= %x eip= %x\n", address, cpu->eip );

	if(disable_mm_logging) return;

	if(address == 0x251ea0+0xC)  ov_inload_list = true;
	if(address == 0x251ea0+0x14) ov_inmem_list  = true;
	if(address == 0x251ea0+0x1C) ov_ininit_list = true;
	if(address == 0x00253320)    ov_basedll_name = true;

	if( !opts.mem_monitor ) return;

	while(mm_points[i].address != 0){
		if(address == mm_points[i].address){
			mm_points[i].hitat = last_good_eip ; //we dont want a long long list, just last one probably only from one spot anyway..
			break;
		}
		i++;
	}

}

void mm_range_callback(char id, char mode, uint32_t address){

	//printf("in mm_range_callback addr= %x eip= %x\n", address, cpu->eip );

	char disasm[200]={0};
	int ret = 0;
	int i;
	char buf[255]={0};
	char *dll=0;
	unsigned char b;
	uint32_t v;

	if(disable_mm_logging) return;

	//some opcodes send us a read and a write ignore these.. 
	if(mdll_last_read_eip == last_good_eip && mdll_last_read_addr==address && mode =='w') return;

	if( isDllMemAddress(last_good_eip) ) return;

	if(cpu->eip == address) return;
	if(last_good_eip == address) return;
    if(address < 0x1000) return;

	if(id == 0x66){ //modifying self in memory; catch all events with this ID - always return if this id
		if(mode=='w'){
			v = last_good_eip;// address;
			emu_memory_read_byte(mem, v, &b);
			if( b != 0x8B && b != 0 ){ /* why need to ignore mov edi,edi, null mem ? */
				for(i=0;i<10;i++){
					if(ov_decode_self_addr[i] == v) break; //no duplicates
					if(ov_decode_self_addr[i] == 0){
						ov_decode_self_addr[i] = v;
						break;
					}
				}
			}
			//("code changed! id=%x mode=%c addr=%x i=%d\n", id, mode, address, i);
		}
		return;
	}

	if(mode == 'r') ov_reads_dll_mem = true;
	if(mode == 'w') ov_writes_dll_mem = true;

	if(mode=='r'){
		mdll_last_read_eip  = last_good_eip;
		mdll_last_read_addr = address;
	}

	//printf("lastgoodeip=%x\n", last_good_eip);
	emu_disasm_addr(cpu, last_good_eip, disasm);
    ret = fulllookupAddress(address, (char*)&buf);	  

	//----------------------- extended mm mode code (run with mm mode)
	if(mode=='w'){
		for(i=0;i<10;i++){

			if( emm.patches[i].addr == address ||
				(emm.patches[i].addr < address && 
				 emm.patches[i].addr+10 >= address)
				) 
				break; //no duplicates, allow up to 10 bytes sequential without second alert..

			if( emm.patches[i].eip == 0 ){
				emm.patches[i].eip = last_good_eip;
				emm.patches[i].addr = address;
				emm.patches[i].name = strdup(buf);
				break;
			}

		}
	}

	if(mode=='r'){
		if(strstr(disasm, "0xe8") > 0 || strstr(disasm, "0xe9") > 0){
			for(i=0;i<10;i++){
				if( emm.hooks[i].addr == address) break; //only show unique addresses
				if( emm.hooks[i].eip  == 0 ){
					emm.hooks[i].eip  = last_good_eip;
					emm.hooks[i].addr  = address;
					emm.hooks[i].name  = strdup(buf);
					break;
				}
			}
		}

		if(strstr(disasm, "0xcc") > 0 ){
			for(i=0;i<10;i++){
				if( emm.bps[i].addr == address) break; //only show unique addresses
				if( emm.bps[i].eip  == 0 ){
					emm.bps[i].eip  = last_good_eip;
					emm.bps[i].addr  = address;
					emm.bps[i].name  = strdup(buf);
					break;
				}
			}
		}
	}

	if(!opts.mem_monitor_dlls) return; 
	//------------------------
	
	while(mm_ranges[ret].start_at !=0){
		if( mm_ranges[ret].id == id){
			dll = mm_ranges[ret].name;
			break;
		}
		ret++;
	}

	start_color(mpurple);
	printf("%x\tmdll %s>\t%s\t %x\t%-10s", last_good_eip, dll, (char*)&disasm[32], address, buf);
	end_color();

	start_color(myellow);
	printf("\t%s\n", mode == 'r' ? "READ" : "WRITE");
	end_color();
	 
}

char* dllFromAddress(uint32_t addr){
	int numdlls=0;
	while ( env->win->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->win->loaded_dlls[numdlls]; 
		if( addr >= dll->baseaddr && addr <= (dll->baseaddr + dll->imagesize) ){
			return dll->dllname;
		}
		numdlls++;
	}
	return strdup(""); //mem leak but no crash choose your fights
}

uint32_t symbol2addr(char* symbol){
	if(symbol == NULL) return 0;
	if(strcmp(symbol,"peb") == 0) return 0x00251ea0;
	if(strcmp(symbol,"fs0") == 0) return FS_SEGMENT_DEFAULT_OFFSET;
	int numdlls=0;
	while ( env->win->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->win->loaded_dlls[numdlls]; 
		struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnname, (void *)symbol);	
		if ( ehi != 0 ){ 
			struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
			return dll->baseaddr + ex->virtualaddr;
		}	
		numdlls++;
	}
	return 0;
}

void symbol_lookup(char* symbol){
	
	bool dllmap_mode = false;

	if(strcmp(symbol,"peb") == 0){
		printf("\tpeb -> 0x00251ea0\n");
		return;
	}

	if(strcmp(symbol,"fs0") == 0){
		printf("\tfs0 -> 0x%x\n", FS_SEGMENT_DEFAULT_OFFSET);
		return;
	}

	if(strcmp(symbol,"dllmap") == 0) dllmap_mode = true;

	int numdlls=0;
	while ( env->win->loaded_dlls[numdlls] != 0 ){
		 
		struct emu_env_w32_dll *dll = env->win->loaded_dlls[numdlls];
		
		if(dllmap_mode){
			printf("\t%-8s Dll mapped at %x - %x  Version: %s\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize, dll->version);
		}
		else{
			if(strcmp(dll->dllname, symbol)==0){
				printf("\t%s Dll mapped at %x - %x  Version: %s\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize, dll->version);
				return;
			}
			
			struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnname, (void *)symbol);
			

			if ( ehi != 0 ){
				int dllBase = dll->baseaddr; 
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
				printf("\tAddress found: %s - > %x\n", symbol, dllBase + ex->virtualaddr);
				return;
			}	
		}
		numdlls++;
	}
	if(!dllmap_mode) printf("\tNo results found...\n");
}

bool isDllMemAddress(uint32_t eip){

	if(eip < 0x71ab0000 || eip > 0x7e4a1000){ 
		if( eip < 0x3d930000 || eip > 0x3da01000) return false;
	}
	return true;
}

int validated_lookup(uint32_t eip){
	char tmp[256];
	if(!isDllMemAddress(eip) ) return 0;
	return fulllookupAddress(eip, &tmp[0]);
}

int fulllookupAddress(int eip, char* buf255){

	int numdlls=0;
	int i=0;
	strcpy(buf255," ");

	//additional lookup for a couple addresses not in main tables..
	while(mm_points[i].address != 0){
		if(eip == mm_points[i].address){
			strcpy(buf255, mm_points[i].name);
			return 1;
		}
		i++;
	}

	while ( env->win->loaded_dlls[numdlls] != 0 )
	{
		if ( eip == env->win->loaded_dlls[numdlls]->baseaddr ){
			
			if(eip == 0x7C800000)
				strcpy(buf255, "Kernel32 Base Address");
			else
				sprintf(buf255, "%s Base Address", env->win->loaded_dlls[numdlls]->dllname );
			
			return 1;
		}
		else if ( eip > env->win->loaded_dlls[numdlls]->baseaddr && 
			      eip < env->win->loaded_dlls[numdlls]->baseaddr + 
				            env->win->loaded_dlls[numdlls]->imagesize )
		{
			struct emu_env_w32_dll *dll = env->win->loaded_dlls[numdlls];
			struct emu_hashtable_item *ehi = emu_hashtable_search(dll->exports_by_fnptr, (void *)(uintptr_t)(eip - dll->baseaddr));

			if ( ehi == 0 )	return 0;

			struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi->value;
			strncpy(buf255, ex->fnname, 254);
			return 1;

		}
		numdlls++;
	}

	return 0;
}


bool find_apiTable(uint32_t offset, uint32_t size){
	
	uint32_t lastApi = symbol2addr(env->win->lastApiCalled);
	//printf("\tStart=%x    End=%x   LastApi=%x\n", offset, offset+size, lastApi);

	if(lastApi == 0) return false;

	uint32_t b;
	uint32_t tableAt = -1;
	int i=0;

	//first try to find a known used address to locate table.
	for(i=0; i < size; i+=4){
		//if(offset+i == 0x401347) printf("at marker!");
		emu_memory_read_dword(mem, offset+i, &b);
		if(b == lastApi){ tableAt = i; break;}
	}

	if(tableAt == -1){ //lets try a 1 byte misaligned search..
		for(i=1; i < size; i+=4){
			emu_memory_read_dword(mem, offset+i, &b);
			if(b == lastApi){ tableAt = i; break;}
		}
		if(tableAt == -1){ //lets try a 2 byte misaligned search..
			for(i=2; i < size; i+=4){
				emu_memory_read_dword(mem, offset+i, &b);
				if(b == lastApi){ tableAt = i; break;}
			}
			if(tableAt == -1){ //lets try a 3 byte misaligned search..
				for(i=3; i < size; i+=4){
					//if(offset+i == 0x401347) printf("at marker!");
					emu_memory_read_dword(mem, offset+i, &b);
					if(b == lastApi){ tableAt = i; break;}
				}
			}
		}	
	}

	if(tableAt == -1) return false; //i give up

	//now search for the table begin..
	i = tableAt-4;
	uint32_t tableStart = -1;
	char *buf = (char*)malloc(256);

	while( i >= 0 ){
		emu_memory_read_dword(mem, offset+i, &b);
		if( validated_lookup(b) == 0 ) break; //not an api address
		tableStart = i;
		i -= 4;
	}

	if( tableStart == -1 ) tableStart = tableAt; //assume we were at first api address...

	uint32_t tableEnd = -1;
	i = tableAt + 4;
	while( i < size){
		emu_memory_read_dword(mem, offset+i, &b);
		if( validated_lookup(b) == 0 ) break; //not an api address
		tableEnd = i;
		i += 4;
	}

	if( tableEnd == -1) tableEnd = tableAt; 

	if( tableStart == tableEnd) return false; //we only found one api address?

	int j=0;
	printf("\n\tFound Api table at: %x\n", offset+tableStart);
	
	for( i=0; i < 8; i++){
		if( tableStart == cpu->reg[i] ){
			printf("\ttable is %s based\n", regm[i]);
			break;
		}
	}
	
	for(i=tableStart; i <= tableEnd; i+=4){
		 emu_memory_read_dword(mem, offset+i, &b);
		 if( fulllookupAddress(b, buf) == 1 ){
			 printf("\t\t[x + %x] = %s\n", j, buf);
		 }
		 j+=4;
	}
	
	return true;
}

void doApiScan(void){

	uint32_t i;

	if( env->win->lastApiCalled == NULL){
		printf("No Api were called can not scan for api table...\n");
	}else{
		printf("\n\nScanning main code body for api table...\n");
		if ( !find_apiTable(opts.baseAddress, opts.size)){
			uint32_t stack_start = cpu->reg[esp];
			int stack_size = cpu->reg[ebp] - cpu->reg[esp];
			if( stack_size < 1 || stack_size > 0x1000) stack_size = 0x1000;
			printf("Scanning stack for api table base=%x sz=%x\n", stack_start, stack_size);
			if(!find_apiTable( stack_start , stack_size )){
				printf("Scanning for register based tables: ");
				for(i=0;i<8;i++){
					printf(" %s,", regm[i]);
					if( find_apiTable( cpu->reg[i] , 0x80 ) ) break;
				}
				nl();
			}
		}
		if( malloc_cnt > 0 ){ //then there were allocs made..
			for(i=0; i < malloc_cnt; i++){
				uint32_t msize = mallocs[i].size;
				if(msize > 0x2600) msize = 0x2600; 
				printf("Scanning memory allocation base=%x, sz=%x\n", mallocs[i].base, msize);
				find_apiTable(mallocs[i].base, msize);
			}
		}
	}

}

uint32_t isString(uint32_t va, uint32_t max_len){ //returns string length
	bool retval = 0;
	char* buf = (char*)malloc(max_len);
	if( emu_memory_read_block(mem, va, buf, max_len) != -1 ){
		for(int i=0;i<max_len;i++){
			unsigned char c = buf[i];
			//61 7A 41 5A 30 31 39 21  3F 2E   azAZ019!?.
			if( isalnum(c)==0 ){
				if( c !='!' && c !='.' && c!='?' && c!=':' && c!='\\' && c!='/' && c!=';' && c!='=') break; 
			}
			retval++;
		}
	}
	free(buf);
	return retval;
}

bool derefStringAddr(struct emu_string* s, uint32_t va, uint32_t len){
		uint32_t slen = isString(va, len);
		if(slen > 0){
			emu_memory_read_string(mem, va, s, slen);
			return true;
		}else{
			emu_string_clear(s);
			return false;
		}
}

bool was_packed(void){
	unsigned char* tmp; int ii;
	tmp = (unsigned char*)malloc(opts.size);
	if(emu_memory_read_block(mem, opts.baseAddress, tmp,  opts.size) == -1) return false;
	for(ii=0;ii<opts.size;ii++){
		if(opts.scode[ii] != tmp[ii]) break;
	}
	return ii < opts.size ? true : false;
}

char* getDumpPath(char* extension){
	
	char* tmp_path;
	char* fname;

	if( opts.temp_dir == NULL || strlen(opts.temp_dir)==0){
		tmp_path = SafeMalloc(strlen(opts.sc_file) + 50);
		strcpy(tmp_path, opts.sc_file);
	}else{
		fname = FileNameFromPath(opts.sc_file);
		tmp_path = SafeMalloc(strlen(opts.temp_dir) + 50 + strlen(fname));
		sprintf(tmp_path, "%s\\%s", opts.temp_dir, fname);
	}

	int x = strlen(tmp_path);
	while(x > 0){ //ida only uses up to first . in idb name so strip all other extensions from base name.
		if(tmp_path[x] == '.') tmp_path[x] = 0; //'_';
		if(tmp_path[x] == '\\' || tmp_path[x] == '/') break;
		x--;
	}
	sprintf(tmp_path,"%s.%s",tmp_path,extension);

	return tmp_path;
}

void do_memdump(void){
	
	unsigned char* tmp ;
	char* tmp_path;
	char* extension[200];
	int ii;
	FILE *fp;

	printf("Primary memory: Reading 0x%x bytes from 0x%x\n", opts.size, opts.baseAddress);
	tmp = (unsigned char*)malloc(opts.size);

	if(emu_memory_read_block(mem, opts.baseAddress, tmp,  opts.size) == -1){
		printf("ReadBlock failed!\n");
	}else{
   	 
		printf("Scanning for changes...\n");
		for(ii=0;ii<opts.size;ii++){
			if(opts.scode[ii] != tmp[ii]) break;
		}

		if(ii < opts.size){
			tmp_path = getDumpPath("unpack");
			start_color(myellow);
			printf("Change found at %i dumping to %s\n",ii,tmp_path);
			fp = fopen(tmp_path, "wb");
			if(fp==0){
				printf("Failed to create file\n");
			}else{
				fwrite(tmp, 1, opts.size, fp);
				fclose(fp);
				printf("Data dumped successfully to disk\n");
			}
			end_color();
			free(tmp_path);
		}else{
			printf("No changes found in primary memory, dump not created.\n");
		}

	}

	free(tmp);

	if( malloc_cnt > 0 ){ //then there were allocs made..
		
		start_color(myellow);
		printf("Dumping %d runtime memory allocations..\n", malloc_cnt);
		
		for(ii=0; ii < malloc_cnt; ii++){
		
			tmp = (unsigned char*)malloc(mallocs[ii].size);

			if(emu_memory_read_block(mem, mallocs[ii].base, tmp,  mallocs[ii].size) == -1){
				printf("ReadBlock failed! base=%x size=%x\n", mallocs[ii].base, mallocs[ii].size );
			}else{
				sprintf((char*)extension,"alloc_0x%x",mallocs[ii].base);
				tmp_path = getDumpPath( (char*)extension);
				fp = fopen(tmp_path, "wb");
				if(fp==0){
					printf("Failed to create file\n");
				}else{
					fwrite(tmp, 1, mallocs[ii].size, fp);
					fclose(fp);
					printf("Alloc %x (%x bytes) dumped successfully to disk as %s\n", mallocs[ii].base, mallocs[ii].size, tmp_path);
				}
				free(tmp_path);
			}

			free(tmp);
		}

		end_color();
			
	}

	free(tmp_path);
}

int file_length(FILE *f)
{
	int pos;
	int end;

	pos = ftell (f);
	fseek (f, 0, SEEK_END);
	end = ftell (f);
	fseek (f, pos, SEEK_SET);

	return end;
}

void dumpFlags(struct emu_cpu *c){

	char *fmsg;
	int sz = 500; //32*3+1
	fmsg = (char *)malloc(sz);
	memset(fmsg, 0, sz);
	sprintf(fmsg, "EFL %x ", cpu->eflags);

	int i;
	for ( i=0;i<32;i++ )
	{
		if ( CPU_FLAG_ISSET(c, i) )
		{
			if(strlen(eflagm[i]) > 0){
				strcat(fmsg, eflagm[i]);
				strcat(fmsg," ");
			}
		}
	}

	start_color(myellow);
	printf(" %s\n", fmsg);
	end_color();

	free(fmsg);

}

void deref_regs(void){

	int i=0;
	int output_addr = 0;
	char ref[255];

	for(i=0;i<8;i++){
		if( fulllookupAddress( cpu->reg[i], (char*)&ref) > 0 ){
			printf("\t%s -> %s\n", regm[i], ref);
			if(output_addr++==3) nl();
		}
	}
	
	struct emu_string* s = emu_string_new();
	bool first = true;

	for(i=0;i<8;i++){
		uint32_t slen = isString(cpu->reg[i], 20);
		if(slen > 0){
			emu_memory_read_string(mem, cpu->reg[i], s, slen);
			if( first ){ printf("\n"); first = false; }
			printf("\t%s -> ASCII: %s %d\n", regm[i], s->data, slen);
			output_addr++;
		}
	}
	
	emu_string_free(s);

	if(output_addr==0) printf("No known values found...");
	nl();
}

void real_hexdump(unsigned char* str, int len, int offset, bool hexonly){
	
	char asc[19];
	int aspot=0;
	int i=0;
    int hexline_length = 3*16+4;
	
	char *nl="\n";
	char *tmp = (char*)malloc(75);
    bool color_on = false;
	uint32_t display_rows = -1;
    uint32_t displayed_lines = -1;
	CONSOLE_SCREEN_BUFFER_INFO csb;

	if(GetConsoleScreenBufferInfo( GetStdHandle(STD_OUTPUT_HANDLE) , &csb) !=0){
		display_rows = csb.srWindow.Bottom - csb.srWindow.Top - 2;
	}

	//printf("Display rows: %x\n", display_rows);

	if(!hexonly) printf(nl);
	
	if(offset >=0){
		printf("          0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n");
		printf("%04x   ", offset);
	}

	for(i=0;i<len;i++){

		color_on = false;
		if(str[i] == 0x90 || str[i]== 0xE9 || str[i]== 0xE8 || str[i]== 0xEB) color_on = true;
		if(color_on && hexdump_color) start_color(myellow);

		sprintf(tmp, "%02x ", str[i]);
		printf("%s",tmp);
		
		if(color_on && hexdump_color) end_color();

		if( (int)str[i]>20 && (int)str[i] < 123 ) asc[aspot] = str[i];
		 else asc[aspot] = 0x2e;

		aspot++;
		if(aspot%8==0) printf(" "); //to make figuring out offset easier

		if(aspot%16==0){
			asc[aspot]=0x00;
			if(!hexonly){
				displayed_lines++;
				sprintf(tmp,"    %s\n", asc);
				printf("%s",tmp);
				if(display_rows > 0 && displayed_lines == display_rows){
					if(!opts.automationRun){ 
						displayed_lines = 0;
						printf("-- More --");
						char qq = getch();
						if(qq == 'q') break;
						printf("\n");
					}
				}
			}
			if(offset >=0){
				offset += 16;
				if(i+1 != len) printf("%04x   ", offset);
			}
			aspot=0;
		}

	}

	if(aspot%16!=0){//print last ascii segment if not full line
		if(!hexonly){
			int spacer = hexline_length - (aspot*3);
			while(spacer--)	printf("%s"," ");	
			asc[aspot]=0x00;
			sprintf(tmp, "%s\n",asc);
			printf("%s",tmp);
		}
	}
	
	if(!hexonly) printf("%s",nl);
	free(tmp);

}

void hexdump(unsigned char* str, int len){ //why doesnt gcc support optional args?
	real_hexdump(str,len,-1,false);
}

void disasm_block(int offset, int size){
	int i, bytes_read, base;
	uint8_t b;
	char disasm[200];
	base = offset;
	for(i=0;i<size;i++){
		bytes_read = emu_disasm_addr(cpu, base, disasm); 
		if(bytes_read < 1){
			if(emu_memory_read_byte(mem,base,&b) == -1) break;
			start_color(myellow);
			printf("%x\tdb %X\n", base, b);
			start_color(mgreen);
			base++;
		}else{
			printf("%x\t%s\n", base, disasm);
		}
		base += bytes_read;
	}
}

uint32_t get_instr_length(uint32_t va){
	char disasm[200];
	return emu_disasm_addr(cpu, va, disasm);  
}

int disasm_addr_simple(int va){
	char disasm[200];
	int len=0;
	len = emu_disasm_addr(cpu, va, disasm);
	start_color(mgreen);
	printf("%x   %s\n", va, disasm);
	end_color();
	return len;
}
	
int disasm_addr(struct emu *e, int va){  //arbitrary offset
	
	int instr_len =0;
	char disasm[200];
	struct emu_cpu *cpu = emu_cpu_get(e);
	
	uint32_t retAddr=0;
	uint32_t m_eip     = va;
	instr_len = emu_disasm_addr(cpu, m_eip, disasm); 
	
	int foffset = m_eip - opts.baseAddress;
	if(foffset < 0) foffset = m_eip; //probably a stack address.

	start_color(mgreen);
	if(opts.verbose ==1){
		if(opts.cur_step % 5 == 0){
			printf("%x   %s\t\t step: %i\n", m_eip, disasm, opts.cur_step );
		}else{
			printf("%x   %s\n", m_eip, disasm);
		}
	}else{
		int xx_ret = (int)strstr(disasm,"retn 0x");
		if(xx_ret == 0 && strstr(disasm,"ret") > 0){ //to do this right we have to support retn 0x too...
			emu_memory_read_dword(mem, cpu->reg[esp], &retAddr);
			printf("%x   %s\t\t step: %d  foffset: %x", m_eip, disasm, opts.cur_step,  foffset);
			start_color(mpurple);
			printf(" ret=%x\n", retAddr);
			end_color();
		}else{
			printf("%x   %s\t\t step: %d  foffset: %x\n", m_eip, disasm, opts.cur_step,  foffset);
		}
	}
	end_color();

	return instr_len;

}



void show_seh(void){
	
	uint32_t seh = 0;
	uint32_t seh_handler = 0;
	
	emu_memory_read_dword( mem, FS_SEGMENT_DEFAULT_OFFSET, &seh);
	emu_memory_read_dword( mem, seh+4, &seh_handler);

	printf("\tPointer to next SEH record = %08x\n\tSE handler: %08x\n", seh, seh_handler);
	//todo: walk chain? probably not necessary for shellcode..

}

void show_disasm(struct emu *e){  //current line

	uint32_t m_eip = emu_cpu_eip_get(emu_cpu_get(e));

	disasm_addr(e,m_eip);

	if(opts.time_delay > 0){
		if(opts.verbose ==1 || opts.verbose ==2) Sleep(opts.time_delay * 1000);
	}

}

unsigned int read_hex(char* prompt, char* buf){
	unsigned int base = 0;
	uint32_t nBytes = 20;
	int i=0;

	printf("%s: (hex/reg) 0x", prompt);
//	getline(&buf, &nBytes, stdin);
	fgets(buf, nBytes, stdin); 

	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = cpu->reg[i];
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}

	if(strstr(buf, "eip") > 0 ) base = cpu->eip;

	if(base==0){
		base = strtol(buf, NULL, 16); //support negative numbers..
		if(base == INT32_MAX) base = strtoul(buf, NULL, 16); //but in this case assume unsigned val entered
	}

	printf("%x\n",base);

	return base;
}

int read_string(char* prompt, char* buf){
	uint32_t nBytes = 60;
	int i=0;

	printf("%s", prompt);
//	getline(&buf, &nBytes, stdin);
	fgets(buf, nBytes, stdin); 

	i = strlen(buf);
	if(i>0) buf[i-1] = 0; //strip new line
	nl();
	return i-1;
}


unsigned int read_int(char* prompt, char* buf){
	unsigned int base = 0;
	uint32_t nBytes = 20;
	int i=0;

	printf("%s: (int/reg) ", prompt);
//	getline(&buf, &nBytes, stdin);
	fgets(buf, nBytes, stdin); 


	if(strlen(buf)==4){
		for(i=0;i<8;i++){
			if(strstr(buf, regm[i]) > 0 ){
				base = cpu->reg[i];
				//printf("found register! %s = %x\n", regm[i], base);
				break;
			}
		}
	}
	
	if(strstr(buf, "eip") > 0 ) base = cpu->eip;

	if(base==0) base = atoi(buf);
	printf("%d\n",base);

	return base;
}

void show_stack(void){
	
	int i=0;
	//uint32_t curesp = emu_cpu_reg32_get(cpu , emu_reg32::esp);
	uint32_t curesp = cpu->reg[esp];
	uint32_t mretval=0;
	char buf[255];
	struct emu_string* es = emu_string_new();

	for(i = -16; i<=24;i+=4){
		emu_memory_read_dword(mem,curesp+i,&mretval);
		fulllookupAddress(mretval, (char*)&buf);
		derefStringAddr(es, mretval, 256); 
		if(i<0){
			printf("[ESP - %-2x] = %08x\t%s\t%s\n", abs(i), mretval, buf, es->data);
		}else if(i==0){
			printf("[ESP --> ] = %08x\t%s\t%s\n", mretval, buf, es->data);
		}else{
			printf("[ESP + %-2x] = %08x\t%s\t%s\n", i, mretval, buf, es->data);
		}
	}

	emu_string_free(es);
	
}

void savemem(void){
	FILE *fp;
	char fname[255];
	char tmp[255];

	int base = read_hex("Enter base address to dump", (char*)&tmp);
	int size = read_hex("Enter size to dump", (char*)&tmp);

	if(base < 1 || size < 1){
		printf("Invalid base (%x) or size (%x)", base,size);
		return;
	}

	void* buf = malloc(size);

	if(emu_memory_read_block(mem,base,buf,size) == -1){
		printf("Failed to read block...\n");
	}else{
		sprintf(fname,"memdump_0x%x-0x%x.bin", base, base+size);
		fp = fopen(fname,"wb");
		fwrite(buf,1,size,fp);
		fclose(fp);
		printf("Dump saved to %s\n", fname);
	}

	free(buf);
	
}

void show_debugshell_help(void){
	printf( 
			"\n"
			"\t? - help, this help screen, h also works\n"
			"\tv - change verbosity (0-4)\n"
			"\tg - go - continue with v=0 \n"
			"\ts - step, continues execution, ENTER also works\n"
			"\tc - reset step counter\n"
			"\tr - execute till return (v=0 recommended)\n"
			"\tu - unassembled address\n"
			"\tb - break at address\n"
			"\tm - reset max step count (-1 = infinate)\n"
			"\te - set eip\n"
			"\tw - dWord dump,(32bit ints) prompted for hex base addr and then size\n"
			"\td - Dump Memory (hex dump) prompted for hex base addr and then size\n"
			"\tx - execute x steps (use with reset step count)\n"
			"\tt - set time delay (ms) for verbosity level 1/2\n"
			"\tk - show stack\n"
			"\ti - break at instruction (scans disasm for next string match)\n"
			"\tf - dereF registers (show any common api addresses in regs)\n" 
			"\tj - show log of last 10 instructions executed\n" 
			"\to - step over\n" 
			"\t+/- - basic calculator to add or subtract 2 hex values\n"  
			"\t.lp - lookup - get symbol for address\n"  
			"\t.pl - reverse lookup - get address for symbol (special: peb,dllmap,fs0)\n" 
			"\t.api - scan memory for api table\n"
			"\t.seh - shows current value at fs[0]\n"
			"\t.segs - show values of segment registers\n"
			"\t.reg - manually set register value\n"
			"\t.dllmap - show dll map\n"
			"\t.poke1 - write a single byte to memory\n"
			"\t.poke4 - write a 4 byte value to memory\n"
			"\t.savemem - saves a memdump of specified range to file\n"
			"\tq - quit\n\n"
		  );
}

void show_segs(){
	char* segs[] = {"cs" , "ss", "ds", "es", "fs", "gs" };
	for(int i=0;i<6;i++){
		printf("\t%s:%x\n",segs[i],emu_memory_segment_getval(mem, (emu_segment)i) );
	}
}

void interactive_command(struct emu *e){

	printf("\n");
    
	if( opts.automationRun ) return;

	disable_mm_logging = true;

	char *buf=0;
	char *tmp = (char*)malloc(61);
	char lookup[255];
	uint32_t base=0;
	uint32_t size=0;
	uint32_t i=0;
	uint32_t bytes_read=0;
	char x[2]; x[1]=0;
    char c=0;;
	struct emu_string *es = emu_string_new();

	while(1){

		if( (c >= 'a' || c==0) && c != 0x7e) printf("dbg> "); //stop arrow and function key weirdness...
		if( c == '.') printf("dbg> ");

		c = getch();

		if(c=='q'){ opts.steps =0; break; }
		if(c=='g'){ opts.verbose =0; break; }
		if(c=='s' || c== 0x0A) break;
		if(c=='?' || c=='h') show_debugshell_help();
		if(c=='f') deref_regs();
		if(c=='j') showEipLog();
		if(c=='k'){ nl(); show_stack(); nl();}
		if(c=='c'){ opts.cur_step = 0; printf("Step counter has been zeroed\n"); }
		if(c=='t') opts.time_delay = read_int("Enter time delay (1000ms = 1sec)", tmp);

		if(c=='r'){ 
			opts.exec_till_ret = true; 
			opts.verbose =0;
			break;
			//printf("Exec till ret set. Set verbosity < 3 and step.\n"); //annoying rare i want to log it anyway...
		}
		
		if(c=='o'){
			if(previous_eip < opts.baseAddress || previous_eip > (opts.baseAddress + opts.size)) previous_eip = last_good_eip;
			if(previous_eip < opts.baseAddress || previous_eip > (opts.baseAddress + opts.size) ) previous_eip = cpu->eip ;
			if(previous_eip >= opts.baseAddress && previous_eip <= (opts.baseAddress + opts.size) ){
				opts.step_over_bp = previous_eip + get_instr_length(previous_eip);
				opts.verbose = 0;
				start_color(myellow);
				printf("Step over will break at %x\n", opts.step_over_bp);
				end_color();
				break;
			}
			else{
				printf("Could not determine next address? lgip = %x, cureip=%x\n", last_good_eip , cpu->eip);
			}
		}

		if(c=='.'){  //dot commands
			i = read_string("",tmp);
			if(i>0){
				if(strcmp(tmp,"api")==0) doApiScan();
				if(strcmp(tmp,"seh")==0) show_seh();
				if(strcmp(tmp,"segs")==0) show_segs();
				if(strcmp(tmp,"savemem")==0) savemem();
				if(strcmp(tmp,"dllmap")==0) symbol_lookup("dllmap");
				if(strcmp(tmp,"pl")==0){
					i = read_string("Enter symbol to lookup address for: ", tmp);
					symbol_lookup(tmp);
				}
				if(strcmp(tmp,"lp")==0){
					base = read_hex("Enter address to do a lookup on", tmp);
					if(base > 0){
						if( fulllookupAddress(base, (char*)&lookup) > 0){
							printf("\tFound: %s\n", lookup);
						}
					}
				}
				if(strcmp(tmp,"poke4")==0){
					base = read_hex("Enter address to write to", tmp);
					if(base > 0){
						 i = read_hex("Enter value to write", tmp);
						 emu_memory_write_dword(mem,base,i);
					}
				}
				if(strcmp(tmp,"poke1")==0){
					base = read_hex("Enter address to write to", tmp);
					if(base > 0){
						 i = read_hex("Enter value to write", tmp);
						 emu_memory_write_byte(mem,base,(uint8_t)i);
					}
				}
				if(strcmp(tmp,"reg")==0){
					base = read_string("Enter register name to modify:", tmp);
					if(base > 0){
						for(i=0;i<8;i++){
							if(strcmp(regm[i], tmp)==0) break;
						}
						if(i < 8){
							printf("set %s to", regm[i]);
							base = read_hex("", tmp);
							cpu->reg[i] = base;
							nl();
							debugCPU(e,true);
						}
					}
				}
			}
		}

		if(c=='i'){
			i = read_string("Enter the disasm instruction you want to break at:", tmp);
			if(opts.break_at_instr != 0) free(opts.break_at_instr); 
			if(i > 0){
				opts.break_at_instr = strdup(tmp);
				printf("Will break when we see %s in disasm, set verbosity and step", opts.break_at_instr);
			}
		}

		if(c=='x'){
			base = read_int("Execute x steps",tmp);
			opts.log_after_step = base;
			printf("Log after step updated. Now clear steps, set verbosity < 3 and step\n");
		}

		if(c=='v'){
			printf("Enter desired verbosity (0-3):");
			x[0] = getchar();
			opts.verbose = atoi(x);
			printf("%i\n", opts.verbose );
		}

		if(c=='m'){
			base = read_int("Reset Max step count",tmp);
			if(base==0){ printf("Failed to get value...\n");}
			else{ opts.steps = base;}
		}

		if(c=='e'){
			base = read_hex("Set eip", tmp);
			if(base==0){ printf("Failed to get value...\n");}
			else{ emu_cpu_eip_set(emu_cpu_get(e), base);}
		}

		if(c=='u'){
			base = read_hex("Disassemble address",tmp);
			size = read_int("Number of instructions to dump (max 100)", tmp);
			if(size > 100) size = 100;
			for(i=0;i<size;i++){
				bytes_read = disasm_addr(e,base);
				if(bytes_read < 1) break;
				base += bytes_read;
			}
		}

		if(c=='b'){
			opts.log_after_va = read_hex("Break at address",tmp);
			printf("Log after address updated. Now set verbosity < 3 and step\n");
		}

		if(c=='d'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter hex size",tmp);

			buf = (char*)malloc(size);
			if(emu_memory_read_block(mem, base, buf,  size) == -1){
				printf("Memory read failed...\n");
			}else{
				real_hexdump((unsigned char*)buf,size,base,false);
			}
			free(buf);

		}

		if(c=='+'){
			base = read_hex("Enter first number to add", tmp);
			size = read_hex("Enter second number",tmp);
			printf("%x + %x = %x\n", base,size, base+size);
		}

		if(c=='-'){
			base = read_hex("Enter first number to subtract", tmp);
			size = read_hex("Enter second number",tmp);
			printf("%x - %x = %x\n", base,size, base-size);
		}

		if(c=='w'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter words to dump",tmp);
			int rel = read_int("Offset mode 1,2,-1,-2 (abs/rel/-abs/-rel)", tmp);			
			if(rel==0) rel = 1;
			size*=4; //num of 4 byte words to show, adjust for 0 based
		
			if( rel < 1 ){
				for(i=base-size;i<=base;i+=4){
					if(emu_memory_read_dword(mem, i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base );
						break;
					}else{
						fulllookupAddress(bytes_read,(char*)&lookup);
						derefStringAddr(es,bytes_read, 50);
						if(rel == -2){
							printf("[x - %-2x]\t%08x\t%s\t%s\n", (base-i), bytes_read, lookup, es->data );
						}else{
							printf("%08x\t%08x\t%s\t%s\n", i, bytes_read, lookup, es->data);
						}
					}
				}
			}else{
				for(i=0;i<=size;i+=4){
					if(emu_memory_read_dword(mem, base+i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base+i );
						break;
					}else{
						derefStringAddr(es,bytes_read, 50);
						fulllookupAddress(bytes_read,(char*)&lookup);
						if(rel == 2){
							printf("[x + %-2x]\t%08x\t%s\t%s\n", i, bytes_read, lookup, es->data );
						}else{
							printf("%08x\t%08x\t%s\t%s\n", base+i, bytes_read, lookup, es->data);
						}
					}
				}
			}

		}

	}

	printf("\n");
	free(tmp);
	emu_string_free(es);
	disable_mm_logging = false;

}


void debugCPU(struct emu *e, bool showdisasm){

	int i=0;
	//struct emu_memory *m = emu_memory_get(e);


	if( in_repeat ) return;

	if (opts.verbose == 0) return;

	//verbose 1= offset opcodes disasm step count every 5th hit
	//verbose 2= adds register and flag dump
	//verbose 3= adds interactive shell 
	//verbose 4= adds stack dump

	if(showdisasm) show_disasm(e);

	if (opts.verbose < 2) return;

	//show registers 
	for(i=0;i<8;i++){
		printf("%s=%-8x  ", regm[i], cpu->reg[(emu_reg32)i] );
		if(i==3)printf("\n");
	}

	dumpFlags(emu_cpu_get(e));
	printf("\n");

	if (opts.verbose < 3) return;
	if(opts.verbose > 3) show_stack();

	interactive_command(e);

	return;

}

void set_hooks(struct emu_env *env){

	extern int32_t	__stdcall hook_GenericStub(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
	extern int32_t	__stdcall hook_GenericStub2String(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);
	extern int32_t	__stdcall hook_shdocvw65(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);

	#define GENERICHOOK(name) if(emu_env_w32_export_new_hook(env, #name, hook_GenericStub, NULL) < 0) printf("Failed to set generic Hook %s\n",#name);

	#define ADDHOOK(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name, hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name);

	#define HOOKBOTH(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name"A", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"A");\
		if(emu_env_w32_export_new_hook(env, #name"W", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"W");

	//following support both Ascii and Wide api
	HOOKBOTH(PathFileExists);
	HOOKBOTH(LoadLibrary);
	HOOKBOTH(GetTempPath);
    HOOKBOTH(GetTempFileName);
    HOOKBOTH(URLDownloadToFile);
	HOOKBOTH(MoveFile);
    HOOKBOTH(GetModuleFileName);
	HOOKBOTH(URLDownloadToCacheFile);
	HOOKBOTH(CreateProcessInternal);
	HOOKBOTH(CryptAcquireContext);
	HOOKBOTH(OpenService);
	HOOKBOTH(RegOpenKeyEx);
	HOOKBOTH(OpenSCManager);
	HOOKBOTH(CreateFile);
	HOOKBOTH(InternetSetOption);
	HOOKBOTH(CreateProcess);

	ADDHOOK(ExitProcess);
	ADDHOOK(memset);
	ADDHOOK(memcpy);
	ADDHOOK(GetFileSize);
	ADDHOOK(GlobalAlloc);
	ADDHOOK(strstr);
	ADDHOOK(strtoul);
    ADDHOOK(lstrcatA);
	ADDHOOK(strrchr);
	
	//these dont follow the macro pattern..mostly redirects/multitasks
	emu_env_w32_export_new_hook(env, "LoadLibraryExA",  hook_LoadLibrary, NULL);
	emu_env_w32_export_new_hook(env, "ExitThread", hook_ExitProcess, NULL);
	emu_env_w32_export_new_hook(env, "GetFileSizeEx", hook_GetFileSize, NULL);
	emu_env_w32_export_new_hook(env, "LocalAlloc", hook_GlobalAlloc, NULL);
	emu_env_w32_export_new_hook(env, "strcat", hook_lstrcatA, NULL);
    emu_env_w32_export_new_hook(env, "RtlMoveMemory", hook_memcpy, NULL); //kernel32. found first...
    emu_env_w32_export_new_hook(env, "CopyMemory", hook_memcpy, NULL);	

	//-----handled by the generic stub 2 string
	emu_env_w32_export_new_hook(env, "InternetOpenA", hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "InternetOpenUrlA", hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "SHRegGetBoolUSValueA", hook_GenericStub2String, NULL);

	//-----by ordinal
	emu_env_w32_export_new_hook_ordinal(env, "shdocvw", 0x65,  hook_shdocvw65);
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02E1, hook_memset); //have to hook this one by ordinal cause it finds ntdll.memset first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x030d, hook_strstr); //have to hook this one by ordinal cause it finds ntdll.strstr first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x0311, hook_strtoul); //have to hook this one by ordinal cause it finds ntdll.strtoul first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02DF, hook_memcpy); //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x02FE, hook_lstrcatA); //have to hook this one by ordinal cause it finds ntdll  first
	emu_env_w32_export_new_hook_ordinal(env, "msvcrt", 0x030b, hook_strrchr); //have to hook this one by ordinal cause it finds ntdll  first
    emu_env_w32_export_new_hook_ordinal(env, "ntdll", 0x02C7, hook_memcpy);   //RtlMoveMemory found in k32 first...

	//-----handled by the generic stub
	GENERICHOOK(ZwTerminateProcess);
	GENERICHOOK(ZwTerminateThread);
	GENERICHOOK(TerminateThread);
	GENERICHOOK(FreeLibrary);
	GENERICHOOK(GlobalFree);
	GENERICHOOK(GetCurrentProcess);
	GENERICHOOK(TerminateProcess);
	GENERICHOOK(CreateThread);
	GENERICHOOK(GetSystemTime);
	GENERICHOOK(SetSystemTime);
	GENERICHOOK(RtlDestroyEnvironment);
	GENERICHOOK(RevertToSelf);
	GENERICHOOK(RtlExitUserThread);
	GENERICHOOK(FlushViewOfFile);
    GENERICHOOK(UnmapViewOfFile);
	GENERICHOOK(FindClose);
	GENERICHOOK(InternetCloseHandle);
	GENERICHOOK(GetCurrentThread);
	GENERICHOOK(CloseServiceHandle);
	GENERICHOOK(DeleteService);
	GENERICHOOK(AdjustTokenPrivileges)

	ADDHOOK(GetModuleHandleA);
	ADDHOOK(MessageBoxA);
	ADDHOOK(ShellExecuteA);
	ADDHOOK(SHGetSpecialFolderPathA);
	ADDHOOK(MapViewOfFile);
	ADDHOOK(system);
	ADDHOOK(VirtualAlloc);
	ADDHOOK(VirtualProtectEx);
	ADDHOOK(SetFilePointer);
	ADDHOOK(ReadFile);
	ADDHOOK(DialogBoxIndirectParamA);
	ADDHOOK(ZwQueryVirtualMemory);
	ADDHOOK(GetEnvironmentVariableA);
	ADDHOOK(VirtualAllocEx);
	ADDHOOK(WriteProcessMemory);
	ADDHOOK(CreateRemoteThread);
	ADDHOOK(MultiByteToWideChar);
	ADDHOOK(_execv);
	ADDHOOK(fclose);
	ADDHOOK(fopen);
	ADDHOOK(fwrite);
	ADDHOOK(_lcreat);
	ADDHOOK(_lclose);
	ADDHOOK(_lwrite);
	ADDHOOK(_hwrite);
	ADDHOOK(GetTickCount);
	ADDHOOK(WinExec);
	ADDHOOK(Sleep);
	ADDHOOK(DeleteFileA);
	ADDHOOK(CloseHandle);
	ADDHOOK(GetVersion);
	ADDHOOK(GetProcAddress);
	ADDHOOK(GetSystemDirectoryA);
	ADDHOOK(malloc);
	ADDHOOK(SetUnhandledExceptionFilter);
	ADDHOOK(WaitForSingleObject);
	ADDHOOK(WriteFile);
	ADDHOOK(VirtualProtect);
	ADDHOOK(bind);
	ADDHOOK(accept);
	ADDHOOK(bind);
	ADDHOOK(closesocket);
	ADDHOOK(connect);
	ADDHOOK(listen);
	ADDHOOK(recv);
	ADDHOOK(send);
	ADDHOOK(sendto);
	ADDHOOK(socket);
	ADDHOOK(WSASocketA);
	ADDHOOK(WSAStartup);
	ADDHOOK(CreateFileMappingA);
	ADDHOOK(WideCharToMultiByte);
	ADDHOOK(GetLogicalDriveStringsA);
	ADDHOOK(FindWindowA);
	ADDHOOK(DeleteUrlCacheEntryA);
	ADDHOOK(FindFirstFileA);
	ADDHOOK(GetUrlCacheEntryInfoA);
	ADDHOOK(CopyFileA);
	ADDHOOK(EnumWindows);
	ADDHOOK(GetClassNameA);
	ADDHOOK(fread);
	ADDHOOK(IsBadReadPtr);
	ADDHOOK(GetCommandLineA);
	ADDHOOK(SHGetFolderPathA);
	ADDHOOK(CryptCreateHash);
	ADDHOOK(CryptHashData);
	ADDHOOK(CryptGetHashParam);
	ADDHOOK(CryptDestroyHash);
	ADDHOOK(CryptReleaseContext);
	ADDHOOK(InternetConnectA);
	ADDHOOK(HttpOpenRequestA);
	ADDHOOK(HttpSendRequestA);
	ADDHOOK(InternetReadFile);
	ADDHOOK(ControlService);
	ADDHOOK(QueryDosDeviceA);
	ADDHOOK(SHDeleteKeyA);
	ADDHOOK(CreateDirectoryA);
	ADDHOOK(SetCurrentDirectoryA);
	ADDHOOK(GetWindowThreadProcessId);
	ADDHOOK(OpenProcess);
	ADDHOOK(ExpandEnvironmentStringsA);
	ADDHOOK(lstrlenA);
	ADDHOOK(lstrcmpiA);
	ADDHOOK(lstrcpyA);
	ADDHOOK(OpenEventA);
	ADDHOOK(CreateEventA);
	ADDHOOK(_stricmp);
	ADDHOOK(strcmp);
	ADDHOOK(GetThreadContext);
	ADDHOOK(SetThreadContext);
	ADDHOOK(ResumeThread);
	ADDHOOK(GetMappedFileNameA);
    ADDHOOK(ZwUnmapViewOfSection);
	ADDHOOK(SetEndOfFile);
	ADDHOOK(LookupPrivilegeValueA);
	ADDHOOK(OpenProcessToken);
	ADDHOOK(EnumProcesses);
	ADDHOOK(GetModuleBaseNameA);
	ADDHOOK(HttpQueryInfoA);
	ADDHOOK(StrToIntA);
	ADDHOOK(gethostbyname);
	ADDHOOK(ZwQueryInformationFile);
	ADDHOOK(ZwSetInformationProcess);
	ADDHOOK(fprintf);
	ADDHOOK(exit);
	ADDHOOK(GetLocalTime);
	ADDHOOK(ExitWindowsEx);
	ADDHOOK(SetFileAttributesA);
	ADDHOOK(GetLastError);
	ADDHOOK(IsDebuggerPresent);
	ADDHOOK(ZwQueryInformationProcess);
	ADDHOOK(OpenFileMappingA);
	ADDHOOK(time);
	ADDHOOK(srand);
	ADDHOOK(rand);
	ADDHOOK(inet_addr);
	ADDHOOK(wsprintfA);
    ADDHOOK(RtlDecompressBuffer);
	ADDHOOK(RtlZeroMemory);
	ADDHOOK(swprintf);
	ADDHOOK(RtlDosPathNameToNtPathName_U);
	ADDHOOK(ZwOpenFile);
	ADDHOOK(fseek);
	ADDHOOK(gethostname);
	ADDHOOK(SendARP);

}

/* we just cant really support every shellcode can we :( 

004010E0   . C600 01        MOV BYTE PTR DS:[EAX],1   <--triggered exception

$ ==>    > 7C8438FA  /CALL to UnhandledExceptionFilter from kernel32.7C8438F5
$+4      > 0012FBE8  \pExceptionInfo = 0012FBE8

0012FBE8  0012FCDC

0012FCDC  C0000005
0012FCE0  00000000
0012FCE4  00000000
0012FCE8  004010E0  shellcod.004010E0
*/

int handle_UnhandledExceptionFilter(void){
    //ret 0 = handled, ret -1 = unhandled

	unsigned char b;
	emu_memory_read_byte(mem, 0x7c862e62, &b);
	if(b != 0){ //code has been written here..so we handle it..
		start_color(myellow);
		printf("\n%x\tException caught w/ UnhandledExceptionFilter\n", last_good_eip);
		end_color();
		emu_cpu_eip_set(emu_cpu_get(e), 0x7c862e62); 
		//this doesnt work with the popular GlobalAlloc/UEF shellcode..cant replicate that env..
		//but if the code did write to UEF this will at least let it run that code. and if they
		//try to access the exception record itself to get the crash address..that should work too..
		emu_memory_write_dword(mem, 0x10000-0xC, 0xC0000005);
		emu_memory_write_dword(mem, 0x10000, last_good_eip); 
		emu_memory_write_dword(mem, cpu->reg[esp], 0xDEADC0DE);
		emu_memory_write_dword(mem, cpu->reg[esp]+4, 0x10000-0xC);
		return 0;
	}

	return -1;
}
/**/
		

/* 
	FS:[00000000]=[7FFDF000]=0012FF98
	0012FF98  0012FFE0  Pointer to next SEH record
	0012FF9C  0040140B  SE handler

	- set registers for exception (observed from debugger not sure of actual docs)
	- zero out eax, ebx, esi, edi
	- set ecx to handler address
	- set edx to next handler 
	- [ESP+8] must = esp before exception
		- add 8 to esp and write value there to be current esp
	
	seems to work, done from observed tested in olly - dzzie

    todo: should we also check the UnhandledExceptionFilter (0x7c862e62) here if its set?
*/
int handle_seh(struct emu *e,int last_good_eip){
			
		int i=0;
		int regs[8];
	    uint32_t seh = 0;
		uint32_t seh_handler = 0;
		const int default_handler = 0x7c800abc;
		struct emu_memory *m = emu_memory_get(e);
		
		//lets check and see if an exception handler has been set
		if(emu_memory_read_dword( m, FS_SEGMENT_DEFAULT_OFFSET, &seh) == -1) return -1;
		if(emu_memory_read_dword( m, seh+4, &seh_handler) == -1) return -1;
		if(seh_handler == 0) return -1; //better to check to see if code section huh?
		if(seh_handler == default_handler) return -1; //not a real one dummy we put in place..

		 
		if( seh_handler == lastExceptionHandler){
			exception_count++; //really here is where we should walk the chain...
			if(exception_count >= 2) return -1;
			//if(seh == 0xFFFFFFFF) return -1;
		}else{
			exception_count=0; 
			lastExceptionHandler = seh_handler;
		}
		 

		start_color(myellow);
		printf("\n%x\tException caught SEH=0x%x (seh foffset:%x)\n", last_good_eip, seh_handler, seh_handler - opts.baseAddress);
		
		//now take our saved esp, add two ints to stack (subtract 8) and set org esp pointer there.
		uint32_t cur_esp = cpu->reg[esp];
		uint32_t new_esp = cur_esp - 8; //make room on stack for seh args
		
		if (opts.verbose >= 1) printf("\tcur_esp=%x new_esp=%x\n\n",cur_esp,new_esp); 
		end_color();
		
		debugCPU(e,false);

		emu_cpu_eip_set(emu_cpu_get(e), seh_handler);

		regs[eax] = 0;
		regs[ebx] = 0;
		regs[esi] = 0;
		regs[edi] = 0;
		regs[ecx] = seh_handler;
		regs[edx] = 0xDEADBEEF; //unsure what this is was some ntdll addr 0x7C9032BC
		regs[esp] = new_esp;

		//update the registers with our new values
		for (i=0;i<8;i++) cpu->reg[(emu_reg32)i] = regs[i];

		uint32_t write_at  = new_esp + 8;
		emu_memory_write_dword(m, write_at, cur_esp); //write saved esp to stack

		return 0; //dont break in final error test..give it a chance...to work in next step

}


uint32_t mini_run(uint32_t limit, struct result *r, bool debug){

	uint32_t steps=0, lastGoodEip=0;
	r->parse_error = 0;
	r->step_error = 0;
	r->foundExport = 0;
	r->overLimit =0;
	r->inDllMemory =0;

	while (1)
	{
		if ( emu_cpu_parse(cpu)== -1 ){r->parse_error=1; break;}
		if ( emu_cpu_step(cpu) == -1 ){r->step_error=1; break;}

		lastGoodEip = cpu->eip;
		if(debug) logEip(lastGoodEip);

		if(steps >= limit){r->overLimit=1; break;}
		steps++; //can not use if(!cpu->repeat_current_instr) test bcause a huge loop = app hang
		
		struct emu_env_w32_dll_export *ex = emu_env_w32_eip_check(env); //this can display hook output if hooks were set..more precise than isdllmemaddress..
		
		if ( ex != NULL){
			cpu->eip = lastGoodEip;
			r->foundExport=1;
			break;
		}

		if( isDllMemAddress(cpu->eip) ){
			r->inDllMemory=1;
			break;  //bails on dll mem addr (we dont have hooks set cause no output wanted, if end eip = an api address good sign!)
		}

		if( cpu->instr.opc == 0 ) break; //we will consider 0000 add [eax], eax as invalid memory.. 
	}
	 
	r->steps = steps;
	r->final_eip = cpu->eip;
	if(debug) memcpy(&r->eip_log, eip_log, eip_log_sz * 4);

	//if(debug) printf("%x ", lastGoodEip);
	return steps;
}

int find_max(struct result results[], int cnt){
	
	int i=0;
	int max_step_cnt=0;
	int max_offset=0;

	while(1){
		if(i > cnt) break;
		if( results[i].steps > max_step_cnt){
			max_step_cnt = results[i].steps;
			max_offset = i;
		}
		i++;
	}
	if(max_step_cnt==0) return -1;
	return max_offset;
}

int find_sc(void){ //loose brute force let user decide...
	
	uint32_t i, ret, s, j, start_time, end_time;    
	uint32_t limit = 250000;
    char buf[20];
    uint32_t last_offset= -2, last_step_cnt=0;
	struct result results[41];
	struct result sorted[11];
	int regs[] = {0,0,0,0,0x12fe00,0x12fff0,0,0};
	char buf255[255];
	
	bool debug = opts.hexdump_file; //not worth its own cmdline option, so reuse this one...(-dump with -findsc = this special debug mode for findsc function...)
	if(opts.hexdump_file) opts.hexdump_file = false; //makes no sense to use after running -findsc anyway...
	if(debug) limit = limit * 5;

	j=0;
	regs[0]=0;

	memset(&results,0,sizeof(struct result)*41);
	int r_cnt = -1;

	if(!opts.automationRun ){
		start_color(colors::myellow);
		printf("Testing %d offsets  |  Percent Complete:    ", opts.size - opts.offset);
		start_time = GetTickCount();
	}

	//printf("opts.offset = %d\n", opts.offset);
	
	for(i=opts.offset; i < opts.size ; i++){

		if(i%10==0 && !opts.automationRun){
			int pcent = (100*i)/opts.size;
			printf("\b\b\b%02d%%", pcent);
			fflush(stdout);
		}

		if( ctrl_c_count > 0 ){
			printf("Control-C detected aborting run, currently at offset 0x%x\n", i);
			break;
		}
		
		/*if( i == 0x10a){
			i = i; //for debugging breakpoint 
		}*/

		emu_cpu_free(cpu);    //  \__not sure why need these next two to prevent bug...
		cpu = emu_cpu_new(e); //  /
		
		init_emu();
		//emu_memory_write_block(mem, opts.baseAddress, opts.scode,  opts.size);
		
		//if(debug){set_hooks(env); start_color(colors::mgreen); printf("| off=%x ", i); end_color();}

		for (j=0;j<8;j++) cpu->reg[j] = regs[j];

		struct result tmpr;
		memset(&tmpr, 0, sizeof(struct result));

		if( opts.scode[i] != 0 ){
			cpu->eip = opts.baseAddress + i;
			s = mini_run(limit,&tmpr,debug); //   v-- start offset must be at least 10 bytes away from final eip rva - (excludes tight loops from garbage)
			//if(debug) printf("s=%x pe=%d se=%d ", s, parse_error, step_error);
			if(s > opts.min_steps && abs(opts.baseAddress + i - cpu->eip ) > 10 /*&& cpu->eip > (opts.baseAddress + i + opts.min_steps)*/ ){
				if(last_step_cnt >= s && (last_offset+1) == i ){ //try not to spam
					last_offset++;
				}else{
					r_cnt++;
					if(r_cnt > 40) break;
					results[r_cnt] = tmpr;
					results[r_cnt].offset = i;
					results[r_cnt].org_i  = i;
					last_offset = i;
					last_step_cnt = s;
					if( fulllookupAddress(cpu->eip, (char*)&buf255) == 1 ){ //run ends in an api address its shellcode so cheat and move to front of sort
						results[r_cnt].steps = limit;
					}
				}
			}
		}


	}

	if(!opts.automationRun ){
		end_time = GetTickCount();
		printf("  |  Completed in %d ms\n", (end_time - start_time) );
		end_color();
	}

	if( r_cnt == -1 ){
		printf("No shellcode detected..\n");
		return -1;
	}

	if( opts.automationRun ){
		s = find_max(results,40);
		if(s == -1) return -1;
		printf("Starting at offset: %x\n",results[s].offset);
		return results[s].offset;
	}
	
	//let them choose from the top 10
	for(i=0;i<10;i++){
		s = find_max(results,40); //if end eip = an api address we should move to top of list..
		if(s == -1) break;
		sorted[i] = results[s];
		fulllookupAddress(results[s].final_eip, (char*)&buf255); 

		if(debug)
			start_color( colors::mwhite ) ;
		else
			start_color( ((i%3==0) ? colors::mgrey : colors::mdkgrey) ) ;
		
		if(results[s].steps == limit) 
			printf("%d) offset=0x%-8x   steps=MAX    final_eip=%-8x   %s", i, results[s].offset, results[s].final_eip, buf255 );
		 else 
			printf("%d) offset= 0x%-8x   steps=%-8d   final_eip= %-8x   %s", i, results[s].offset , results[s].steps , results[s].final_eip, buf255);
		
		end_color();

		if(debug){
			start_color(colors::mgreen);
			printf("\n\tStepError: %d  ParseError %d  FoundExport %d  InDllMem: %d  Last10Inst:\n", results[s].step_error, results[s].parse_error, results[s].foundExport, results[s].inDllMemory); 
			
			for(int i=0;i < eip_log_sz;i++){
				if(results[s].eip_log[i] == 0) break; 
				disasm_addr_simple(results[s].eip_log[i]);
			}

			end_color();
		}

		if(opts.disasm_mode > 0){
			real_hexdump(opts.scode + results[s].offset, opts.disasm_mode, -1, true);
			nl();
			start_color(mgreen);
			disasm_block(opts.baseAddress + results[s].offset, opts.disasm_mode);
			end_color();
		}

		nl();
		results[s].steps = -1; //zero out this entry so it wont be chosen again
	}	

	if(i==1){
		return sorted[0].offset; //there was only one to choose from just run it..
	}

	opts.disasm_mode = 0;
	ret = read_int("\nSelect index to execute:",(char*)&buf);
    if(ret < 0 ) return -1;
	if(ret > (i-1) ) return -1; // i = number of results in sorted..

	emu_cpu_free(cpu);     
	cpu = emu_cpu_new(e);  

	return sorted[ret].offset;

}

void init_emu(void){
	
	int i =  0;
	void* stack;
	int stacksz;

	for (i=0;i<8;i++) cpu->reg[i] = regs[i];

	stacksz = regs[ebp] - regs[esp] + 500;
	stack = malloc(stacksz);
	memset(stack, 0, stacksz);
	
	//printf("writing initial stack space\n");
	emu_memory_write_block(mem, regs[esp] - 250, stack, stacksz);

	/*  support the topstack method to find k32 base...
		00401003   64:8B35 18000000 MOV ESI,DWORD PTR FS:[18]
		0040100A   AD               LODS DWORD PTR DS:[ESI]
		0040100B   AD               LODS DWORD PTR DS:[ESI]
		0040100C   8B40 E4          MOV EAX,DWORD PTR DS:[EAX-1C]
	*/
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0x18, FS_SEGMENT_DEFAULT_OFFSET); //point back to fs0
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0x4, 0x00130000); // Top of thread's stack
	emu_memory_write_dword(mem, 0x00130000 - 0x1c, 0x7C800abc); //technically a seh addr in k32 here set to work with the libemu mem map

	/* support seh method to find k32 base */
	emu_memory_write_dword(mem, FS_SEGMENT_DEFAULT_OFFSET + 0, 0x00130000); //address of current seh handler
	emu_memory_write_dword(mem, 0x00130000, 0xFFFFFFFF);   //end of seh chain
	emu_memory_write_dword(mem, 0x00130000+4, 0x7C800abc); //mock handler in k32

	/* support writes to UnhandledExceptionFilter, MessaegBeep */
	emu_memory_write_dword(mem, 0x7c862e62, 0);   //uef
	emu_memory_write_dword(mem, 0x7c862e62+4, 0);
	emu_memory_write_dword(mem, 0x7e431f7b, 0);   //messaegbeep
	emu_memory_write_dword(mem, 0x7e431f7b+4, 0);
	/**/

	//some of the shellcodes look for hooks set on some API, lets add some mem so it exists to check
    emu_memory_write_dword(mem, 0x7df7b0bb, 0x00000000); //UrldownloadToFile
	
	//write shellcode to memory
	emu_memory_write_block(mem, opts.baseAddress, opts.scode,  opts.size);
	
	unsigned char tmp[0x1000]; //extra buffer on end in case they expect it..
	memset(tmp, 0, sizeof(tmp));
	emu_memory_write_block(mem, opts.baseAddress + opts.size+1,tmp, sizeof(tmp));
	

}

int run_sc(void)
{

	int i =  0;
	int j =  0;
	int ret;
	char disasm[200];
    bool firstchance = true;
	uint32_t eipsave = 0;
	bool parse_ok = false;
	//struct emu_vertex *last_vertex = NULL;
	//struct emu_graph *graph = NULL;
	struct emu_hashtable *eh = NULL;
	struct emu_hashtable_item *ehi = NULL;

	//printf("Setting eip\n");
	emu_cpu_eip_set(emu_cpu_get(e), opts.baseAddress + opts.offset);  //+ opts.offset for getpc mode

	set_hooks(env);

	disable_mm_logging = false;

//----------------------------- MAIN STEP LOOP ----------------------
	opts.cur_step = -1;
	while(1)
	{
	
		opts.cur_step++;
		j = opts.cur_step;
		ctrl_c_count = 0;

		if(opts.steps >= 0){ //this allows us to use -1 as run till crash..we can ctrl c so
			if(opts.cur_step > opts.steps) break;
		}

		if(emu_cpu_get(e)->eip  == opts.log_after_va) //we hit the requested eip start logging.
		{
			opts.verbose = opts.verbosity_after;
			opts.log_after_va = 0;
			opts.log_after_step = 0;
		}

		if(emu_cpu_get(e)->eip  == opts.step_over_bp && cpu->eip != 0)
		{
			opts.verbose = 3;
			opts.step_over_bp = -1;
		}

		if( j == opts.log_after_step && opts.log_after_step > 0 )
		{
			opts.verbose = opts.verbosity_after;
			opts.log_after_step = 0;
			opts.log_after_va = 0;
		}

		if( opts.break_above != 0 && last_good_eip > opts.break_above){
			opts.verbose = 3;
			opts.break_above = 0;
			start_color(myellow);
			printf("Break Above hit...\n");
			end_color();
		}

		if(opts.break0){
			if(cpu->instr.cpu.opc == 0 && opts.cur_step > 0){
				opts.verbose = 3; //interactive dbg prompt
				start_color(myellow);
				printf("break 0 hit\n");
				end_color();
			}
		}

		if ( cpu->repeat_current_instr == false ){
			eipsave = emu_cpu_eip_get(emu_cpu_get(e));
			logEip(eipsave);
		}
		struct emu_env_w32_dll_export *ex = NULL;

		ex = emu_env_w32_eip_check(env);

		//ignore UnhandledExceptionFilter && MessageBeep
		if ( ex != NULL  && cpu->eip != 0x7c862e62 && cpu->eip != 0x7e431f7b) 
		{				
			if ( ex->fnhook == NULL )
			{
				//insert generic api handler here
				start_color(myellow);
				if( strlen(ex->fnname) == 0)
					printf("%x\tunhooked call to ordinal %s.0x%x\tstep=%d\n", previous_eip , dllFromAddress(cpu->eip), ex->ordinal, opts.cur_step );
				else
					printf("%x\tunhooked call to %s.%s\tstep=%d\n", previous_eip, dllFromAddress(cpu->eip), ex->fnname, opts.cur_step );
				end_color();
				break;
			}
		}
		else
		{

			if(firstchance == false){ //we are in our seh handled code now debugging stuff here.
					debugCPU(e,true);
			}

			ret = 0;
			parse_ok = true;
			in_repeat = cpu->repeat_current_instr;

			if(opts.verbose > 0 && in_repeat == false) debugCPU(e,true); //show_disasm(e);

//--- PARSE
			ret = emu_cpu_parse(emu_cpu_get(e));

			if(ret == -1){ parse_ok = false; }  // FOR SEH


			struct emu_env_hook *hook =NULL;

			if ( ret != -1 )
			{
				if ( hook != NULL )
				{
					;
				}
				else
				{

/*----- STEP------*/    ret = emu_cpu_step(emu_cpu_get(e));

						if(ret != -1)  //step was ok
						{ 
							previous_eip = last_good_eip;
							last_good_eip = emu_cpu_eip_get(emu_cpu_get(e)); //used in case of seh exception
							if(opts.exec_till_ret == true){
								emu_disasm_addr(emu_cpu_get(e),last_good_eip,disasm);
								if(strstr(disasm,"ret") > 0){
									opts.exec_till_ret = false;
									opts.verbose = 3; //interactive dbg prompt
									//show_disasm(e);
									start_color(myellow);
									printf("Exec till return hit!\n");
									end_color();
								}
							}
							if(opts.break_at_instr != 0){
								emu_disasm_addr(emu_cpu_get(e),last_good_eip,disasm);
								if(strstr(disasm, opts.break_at_instr) > 0){
									opts.verbose = 3; //interactive dbg prompt
									//show_disasm(e);
									start_color(myellow);
									printf("Break at instruction hit!\n");
									end_color();
								}
							}
							firstchance = true;						//step was ok..give it another chance at exception.
							//if(opts.verbose > 0) debugCPU(e,false);	//now show the registers after the instruction executed 
						}
					
				} //end hook != null
				
			} // end ret != -1


//SEH HANDLER CODE
			if( opts.noseh == false){
				if ( ret == -1 && firstchance && parse_ok) 
				{				
					firstchance = false;
					disable_mm_logging = true;
					ret = handle_seh(e, last_good_eip);
					if(ret == -1) { //not handled by seh
						ret = handle_UnhandledExceptionFilter();
					}
					disable_mm_logging = false;
				} 
			}


			if ( ret == -1 )  //unhandled error time to bail
			{
				if(opts.verbose < opts.verbosity_onerr)	opts.verbose = opts.verbosity_onerr; 
				if(opts.verbose < 2) opts.verbose = 2; //always show disasm and regs on error now..

				start_color(mred);
				printf("%x\t %s\n", last_good_eip, emu_strerror(e)); 
				end_color();

				cpu->eip = last_good_eip;
				debugCPU(e,true);
				
				int mva = cpu->eip; //show next 4 lines of disasm for context..
				mva += get_instr_length(mva);
				if(mva != cpu->eip){
					int minst = 1;
					while(minst++ < 5){
						int mlen = disasm_addr_simple(mva);
						if(mlen<1)break;
						mva+=mlen;
					}
				}

				if(opts.verbose < 3) break; //exit step loop if we didnt enter debug shell
			}


		} 

//			printf("\n");
	} //---------------------- end of step loop

	printf("\nStepcount %i\n",j);

	if(opts.dump_mode && opts.file_mode){  // dump decoded buffer
		do_memdump();
	}

	if(opts.report){
		printf("\nAnalysis report:\n");

		if( was_packed() )     printf("\tSample decodes itself in memory.   \t(use -d to dump)\n");
		if( ov_reads_dll_mem ) printf("\tReads of Dll memory detected       \t(use -mdll for details)\n");
		if( ov_writes_dll_mem) printf("\tWrites to Dll memory detected      \t(use -mdll for details)\n");
		if( ov_ininit_list )   printf("\tUses peb.InInitilizationOrder List\n");
		if( ov_inmem_list  )   printf("\tUses peb.InMemoryOrder List\n");
		if( ov_inload_list )   printf("\tUses peb.InLoadOrder List\n");
		if( ov_basedll_name )  printf("\tUses ldrData.BaseDllName\n");

		if( ov_decode_self_addr[0] != 0 ){
			printf("\tInstructions that write to code memory or allocs:\n");
			for(i=0;i<10;i++){
				if(ov_decode_self_addr[i] == 0) break;
				printf("\t");
				disasm_addr_simple(ov_decode_self_addr[i]);
			}
		}

	}

	if( opts.sigScan || opts.report) sigChecks();

	if( opts.findApi) doApiScan();

	if(opts.mem_monitor){
		printf("\nMemory Monitor Log:\n");

		i=0;
		while(mm_points[i].address != 0){
			if(mm_points[i].hitat != 0){
				printf("\t%s accessed at 0x%x\n", mm_points[i].name, mm_points[i].hitat);
			}
			i++;
		}
		
		for(i=0;i<10;i++){
			if(emm.bps[i].eip > 0){
				printf("\tBreakpoint check on addr=0x%x  %s (1st@ 0x%x)\n", emm.bps[i].addr, emm.bps[i].name, emm.bps[i].eip);
			}
		}

		for(i=0;i<10;i++){
			if(emm.hooks[i].eip > 0){
				printf("\tHook Check on addr=0x%x  %s (1st@ 0x%x)\n", emm.hooks[i].addr, emm.hooks[i].name, emm.hooks[i].eip);
			}
		}

		for(i=0;i<10;i++){
			if(emm.patches[i].eip > 0){
				printf("\tApi patching found at 0x%x on addr=0x%x  %s\n", emm.patches[i].eip, emm.patches[i].addr, emm.patches[i].name);
			}
		}

	}

	nl();
	nl();
	emu_env_free(env);
	return 0;
}

/*
int getpctest(void)
{
	struct emu *e = emu_new();
	int offset=0;
	
	start_color(myellow);
	
	if ( (offset = emu_shellcode_test(e, (uint8_t *)opts.scode, opts.size)) >= 0 ){
		printf("Shellcode detected at offset = 0x%04x\n", offset);
		//printf("Would you like to start execution there? (y/n):");
		//offset = getchar() == 'y' ? offset : -2;
	}
	else{
		printf("/getpc mode did not detect any shellcode in the file\n");
		offset = -1;
	}
	emu_free(e);
	
	end_color();
	return offset;
}
*/

void show_help(void)
{
	struct help_info 
	{
		const char *short_param;
		const char *args;
		const char *description;
	};

	struct help_info help_infos[] =
	{
		{"f", "fpath"    ,   "load shellcode from file - accepts binary, %u, \\x, %x, hex blob"},
		{"api", NULL  ,      "scan memory and try to find API table"},
		{"auto", NULL  ,     "running as part of an automation run"},
		{"ba", "hexnum"  ,   "break above - breaks if eip > hexnum"},
		{"bp", "hexnum"  ,   "set breakpoint on addr or api name (same as -laa <hexaddr> -vvv)"},
		{"bs", "int"     ,   "break on step (shortcut for -las <int> -vvv)"},
		{"b0", NULL ,        "break if 00 00 add [eax],al"},
		{"cmd", "\"string data\"","data to use for GetCommandLineA (use \\\" to embed quotes)"},
		{"cfo", NULL ,       "CreateFileOverRide - if /fopen use handle else open real arg"},
		{"d",  NULL	     ,   "dump unpacked shellcode"},
		{"dir", " folder",   "process *.sc in <folder> supports: -r (1 report), -v (report mode), -u"},
		{"disasm", "int" ,   "Disasm int lines (can be used with /foff)"},
		{"dump", NULL,       "view hexdump (can be used with /foff)"},
		{"e", "int"	     ,   "verbosity on error (3 = debug shell)"},
		{"findsc", NULL ,    "detect possible shellcode buffers (brute force) (supports -dump, -disasm)"},
		{"fopen", "file" ,   "Opens a handle to <file> for use with GetFileSize() scanners"},		
		{"foff", "hexnum" ,  "starts execution at file offset (also supports virtual addresses)"},
		{"h",  NULL		 ,   "show this help"},
		{"hex", NULL,        "show hex dumps for hook reads/writes (paged)"},
		{"hooks", NULL ,     "dumps a list all implemented api hooks"},
		{"i",  NULL		 ,   "enable interactive hooks (file and network)"},
		{"las", "int"	 ,   "log at step ex. -las 100"},
		{"laa", "hexnum" ,   "log at address or api ex. -laa 0x401020 or -laa ReadFile"},
		{"lookup", "api" ,   "shows the address of WinAPi function ex. -lookup GetProcAddress"},
		{"mm", NULL,         "enabled Memory Monitor (logs access to key addresses)"},
		{"mdll", NULL,       "Monitor Dll - log direct access to dll memory (hook detection/patches)"},
		{"min", "steps",     "min number of steps (decimal) to trigger record in findsc mode (def 200)"},
		{"nc", NULL,         "no color (if using sending output to other apps)"},
		{"noseh", NULL,      "Disables support for seh and UnhandledExceptionFilter"},
		{"norw", NULL,       "Disables display of read/write file hooks"},
		{"o", "hexnum"   ,   "base offset to use (default: 0x401000)"},
		{"patch", "fpath",   "load patch file <fpath> into libemu memory"},
		{"r", NULL ,         "show analysis report at end of run (includes -mm)"},
		{"redir", "ip:port", "redirect connect to ip (port optional)"},
		{"s", "int"	     ,   "max number of steps to run (def=2000000, -1 unlimited)"},	
		{"sigs", NULL	 ,   "show signatures (can be used with -disasm)"},	
		{"t", "int"	     ,   "time to delay (ms) between steps when v=1 or 2"},
		{"temp", "folder",   "use folder as temp path for interactive mode file writes"},
		{"u", NULL ,         "unlimited steps (same as -s -1)"},
		{"v",  NULL		 ,   "verbosity, can be used up to 4 times, ex. /v /v /vv"},
		{"- /+", NULL ,      "increments or decrements GetFileSize, can be used multiple times"},
		{"va", "0xBase-0xSize","VirtualAlloc memory at 0xBase of 0xSize"}, 
		{"raw", "0xBase-fpath","Raw Patch Mode: load fpath into mem at 0xBase (not PE aware)"}, 
		{"wint", "0xBase-0xVal","Write 32bit integer 0xValue at 0xBase"}, 
		{"wstr", "0xBase-Str","Write string at base ex. 0x401000-0x9090EB15CCBB or \"0xBase-ascii string\""}, 
		{"dllmap", NULL ,     "show the name, base, size, and version of all built in dlls"},
		{"nofile", NULL ,     "assumes you have loaded shellcode manually with -raw, -wstr, or -wint"},
		{"bswap", NULL ,     "byte swaps -f and -wstr input buffers"},
		{"eswap", NULL ,     "endian swaps -f and -wstr input buffers"},
		{"conv", "path" , "outputs converted shellcode to file (%u,\\x,bswap,eswap..)"},
	};

	system("cls");
	start_color(mwhite);
	printf("\n\n");
	printf("  scdbg is an adaption of the libemu library and sctest project\n");
	printf("  Libemu Copyright (C) 2007  Paul Baecher & Markus Koetter\n");
	printf("  scdbg developer: David Zimmer <dzzie@yahoo.com>\n");
	printf("  Compile date: %s %s\n\n", __DATE__, __TIME__);
	end_color();

	for (int i=0;i<sizeof(help_infos)/sizeof(struct help_info); i++)
	{
		printf("  /%1s ", help_infos[i].short_param);

		if (help_infos[i].args != NULL)
			printf("%-12s ", help_infos[i].args);
		else
			printf("%12s "," ");

		printf("\t%s\n", help_infos[i].description);
	}

	printf("\n   in the dbg> shell enter ? to see supported commands\n\n");
	//show_debugshell_help();
	exit(0);

}

void show_supported_hooks(void){
	
	uint32_t i=0;
	uint32_t j=0;
	uint32_t tot=0;
	uint32_t iHooks=0;
	uint32_t proxied=0;

	set_hooks(env);

	while ( env->win->loaded_dlls[i] != 0 ){
		struct emu_env_w32_dll *dll = env->win->loaded_dlls[i]; 
		printf("\r\n%s\r\n", dll->dllname );
		emu_env_w32_dll_export e = dll->exportx[0];
		while( e.fnname != NULL ){
			if( e.fnhook != 0 ){
				if( strlen(e.fnname) == 0){
					printf("\t  @%x\r\n", e.ordinal);
				}else if( isInteractive(e.fnname) ){
					start_color(myellow);
					printf("\t  %s\r\n", e.fnname);
					end_color();
					iHooks++;
				}else if( isProxied(e.fnname) ){
					start_color(myellow);
					printf("\t* %s\r\n", e.fnname);
					end_color();
					proxied++;
				}else{
					printf("\t  %s\r\n", e.fnname);
				}				
				tot++;
			}
			j++;
			e = dll->exportx[j];
			//if( IsBadReadPtr(e.fnname ,4) ) break; //emu_env_w32_dll_exports_copy was not copying last null element fixed
		}
		i++;
		j=0;
	}
	//libemu 2.0 is 5 dlls, 51 hooks, 234 opcodes
	//cur:          12     187        244
	printf("\r\n  Dlls: %d\r\n  Hooks: %d\r\n  Interactive: %d (yellow)\r\n *Proxied: %d\r\n", i, tot, iHooks, proxied);
	printf("  Opcodes: %d\r\n", emu_cpu_implemented_inst_cnt() );
	exit(0);
}

void byteSwap(unsigned char* buf, uint32_t sz, char* id){
	
	if(strlen(id) > 0) printf("Byte Swapping %s input buffer..\n", id);
	unsigned char a,b;
	for(int i=0; i < sz-1; i+=2){
		a = buf[i];
        b = buf[i+1];
        buf[i] = b;
		buf[i+1] = a;
	}

}

void endianSwap(unsigned char* buf, uint32_t sz, char* id){
	
	if(strlen(id) > 0) printf("Endian Swapping %s input buffer..", id);
	
	uint32_t mod = sz % 4;
	if(mod!=0) printf("size %% 4 != 0, wont swap last %d bytes..", mod);
	nl();

	uint32_t a;
	for(int i=0; i < sz-3; i+=4){
		memcpy(&a, (void*)&buf[i],4);
        a = htonl(a);
        memcpy((void*)&buf[i],&a,4);
	}

}


/*
	this func may be a bit verbose and ugly, but I cant crash it or get it to bug out
	so I cant gather the will to change it. plus I have no shame 
	step 1..make it work. step 2 use it  -dzzie
*/
void parse_opts(int argc, char* argv[] ){

	int i;
	int sl=0;
	char buf[5];
    
	opts.sc_file[0] = 0;
	opts.opts_parsed = 1;
	opts.verbosity_onerr = 0;
	opts.verbosity_after =0;
	opts.offset = 0;
	opts.steps = 2000000;
	opts.file_mode = false;
	opts.dump_mode = false;
	opts.mem_monitor = false;
	opts.no_color = false;
	opts.exec_till_ret = false;
	opts.mem_monitor_dlls = false;
	opts.report = false;
	opts.CreateFileOverride = false;
	opts.findApi = false;
	opts.baseAddress = 0x00401000;
	opts.sigScan = false;
	opts.automationRun = false;
	opts.noseh = false;
	opts.min_steps = 200;
	opts.norw = false;
	opts.rop = false;
	opts.nofile = false;
    opts.eSwap = false;
	opts.bSwap = false;
	opts.convert_outPath = 0;

	for(i=1; i < argc; i++){

		bool handled = false;			
		sl = strlen(argv[i]);

		if( argv[i][0] == '-') argv[i][0] = '/'; //standardize

		buf[0] = argv[i][0];
		buf[1] = argv[i][1];
		buf[2] = '0';
		 		
		if(sl==2 && strstr(buf,"/-") > 0 ){ opts.adjust_getfsize-- ;handled=true;}
		if(sl==2 && strstr(buf,"/+") > 0 ){ opts.adjust_getfsize++ ;handled=true;}
		if(sl==2 && strstr(buf,"/i") > 0 ){opts.interactive_hooks = 1;handled=true;}
		if(sl==2 && strstr(buf,"/v") > 0 ){opts.verbose++; handled=true;}
		if(sl==2 && strstr(buf,"/r") > 0 ){ opts.report = true; opts.mem_monitor = true;handled=true;}
		if(sl==2 && strstr(buf,"/u") > 0 ){opts.steps = -1;handled=true;}
		if(sl==6 && strstr(argv[i],"/eswap") > 0 ){   opts.eSwap = true; handled=true;}
		if(sl==6 && strstr(argv[i],"/bswap") > 0 ){   opts.bSwap = true; handled=true;}
		if(sl==4 && strstr(argv[i],"/rop") > 0 ){   opts.rop = true; handled=true;}
		if(sl==5 && strstr(argv[i],"/norw") > 0 ){   opts.norw = true; handled=true;}
		if(sl==6 && strstr(argv[i],"/noseh") > 0 ){   opts.noseh = true; handled=true;}
		if(sl==3 && strstr(argv[i],"/nc") > 0 ){   opts.no_color = true; handled=true;}
		if(sl==5 && strstr(argv[i],"/sigs") > 0 ){ showSigs(); exit(0); }
		if(sl==5 && strstr(argv[i],"/auto") > 0 ){ opts.automationRun = true; handled = true; }
		if(sl==3 && strstr(argv[i],"/b0") > 0 ){   opts.break0  = true;handled=true;}
		if(sl==4 && strstr(argv[i],"/hex") > 0 ) { opts.show_hexdumps = true;handled=true;}
		if(sl==7 && strstr(argv[i],"/findsc") > 0 ){ opts.getpc_mode = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/vvvv") > 0 ){handled=true; opts.verbose = 4;}
		if(sl==4 && strstr(argv[i],"/vvv") > 0 ) { opts.verbose = 3;handled=true;}
		if(sl==3 && strstr(argv[i],"/vv")  > 0 ) { opts.verbose = 2;handled=true;}
		if(sl==3 && strstr(argv[i],"/mm")  > 0 )  {opts.mem_monitor = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/mdll")  > 0 ){  opts.mem_monitor_dlls  = true;handled=true;}
		if(sl==4 && strstr(argv[i],"/api")  > 0 ){  opts.findApi = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/dump")  > 0 ){  opts.hexdump_file = 1;handled=true;}
		if(sl==6 && strstr(argv[i],"/hooks")  > 0 ){ show_supported_hooks();handled=true;}
		if(sl==4 && strstr(argv[i],"/cfo")  > 0 ){ opts.CreateFileOverride = true;handled=true;}
		if(sl==2 && strstr(buf,"/d") > 0 ){ opts.dump_mode = true;handled=true;}
		if(sl==2 && strstr(buf,"/h") > 0 ){ show_help();handled=true;}
		if(sl==2 && strstr(buf,"/?") > 0 ){ show_help();handled=true;}
		if(sl==5 && strstr(argv[i],"/help") > 0 ){ show_help();handled=true;}
		if(sl==7 && strstr(argv[i],"/dllmap") > 0 ){ nl(); symbol_lookup("dllmap");exit(0);}
		if(sl==7 && strstr(argv[i],"/nofile") > 0 ){ opts.nofile = true;handled=true;}

		if(sl==5 && strstr(argv[i],"/temp") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /temp must specify a folder path as next arg\n");
				exit(0);
			}
			opts.temp_dir = strdup(argv[i+1]);
			if( !FolderExists(opts.temp_dir) ){
				start_color(myellow);
				printf("/temp argument must be a valid folder path.\nFolder not found: %s", opts.temp_dir);
				end_color();
				exit(0);
			}
			if( strlen(opts.temp_dir) > 255){
				start_color(myellow);
				printf("Sorry /temp argument must be less than 255 chars in length.."); //im lazy
				end_color();
				exit(0);
			}
			if(!opts.automationRun) printf("temp directory will be: %s\n", opts.temp_dir);
			i++;handled=true;
		}

		if(sl==2 && strstr(buf,"/f") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /f must specify a file path as next arg\n");
				exit(0);
			}
			strncpy(opts.sc_file, argv[i+1],499);
			opts.file_mode = true;
			i++;handled=true;
		}
		
		if(sl==6 && strstr(argv[i],"/patch") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /patch must specify a file path as next arg\n");
				exit(0);
			}
			opts.patch_file = strdup(argv[i+1]);
			i++;handled=true;
		}

		if(sl==5 && strstr(argv[i],"/conv") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /conv must specify a file path as next arg\n");
				exit(0);
			}
			opts.convert_outPath = strdup(argv[i+1]);
			i++;handled=true;
		}

		if(sl==7 && strstr(argv[i],"/lookup") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /lookup must specify an API name as next arg\n");
				exit(0);
			}
			uint32_t addr = symbol2addr(argv[i+1]);
			if( addr == 0)
				printf("\nNo results found for: %s\n\n",argv[i+1]);
			else
				printf("\n%s = 0x%x\n\n",argv[i+1],addr);
			exit(0);
			
		}
		
		if(sl==4 && strstr(argv[i],"/cmd") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /cmd command line for GetCommandLineA as next arg\n");
				exit(0);
			}
			opts.cmdline = strdup(argv[i+1]);
			i++;handled=true;
		}

		if(sl==4 && strstr(argv[i],"/dir") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /dir must specify a folder path as next arg\n");
				exit(0);
			}
			opts.scan_dir = strdup(argv[i+1]);
			i++;handled=true;
		}

		if(sl==2 && strstr(buf,"/o") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /o must specify a hex base addr as next arg\n");
				exit(0);
			}
		    opts.baseAddress = strtol(argv[i+1], NULL, 16);			
			i++;handled=true;
		}

		if(sl==4 && strstr(argv[i],"/min") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /min must specify min number of decimal steps (findsc mode) as next arg\n");
				exit(0);
			}
		    opts.min_steps = atoi(argv[i+1]);			
			i++;handled=true;
		}

		if(sl==6 && strstr(argv[i],"/fopen") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /foopen must specify file to open as next arg\n");
				exit(0);
			}
			//opts.fopen = fopen(argv[i+1],"r");  //ms implemented of fread barfs after 0x27000?
			opts.h_fopen = CreateFile(argv[i+1],GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
			opts.fopen_fpath = strdup(argv[i+1]);
			opts.fopen_fsize = GetFileSize(opts.h_fopen,0);//file_length(opts.fopen);
			//if((int)opts.fopen < 1){
			if( opts.h_fopen == INVALID_HANDLE_VALUE){
				start_color(myellow);
				printf("FAILED TO OPEN %s", argv[i+1]);
				end_color();
				exit(0);
			}
			if(!opts.automationRun) printf("fopen(%s) = %x\n", argv[i+1], (int)opts.h_fopen);
			i++;handled=true;
		}

		if(sl==5 && strstr(argv[i],"/foff") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /foff must specify start file offset as next arg\n");
				exit(0);
			}
			opts.offset = strtol(argv[i+1], NULL, 16);
			i++;handled=true;
		}

		if(sl==3 && strstr(argv[i],"/bp") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /bp must specify hex breakpoint addr as next arg\n");
				exit(0);
			}
			opts.log_after_va = symbol2addr(argv[i+1]);
			if(opts.log_after_va == 0) opts.log_after_va = strtol(argv[i+1], NULL, 16);
			opts.verbosity_after = 3;
			i++;handled=true;
		}

		if(sl==3 && strstr(argv[i],"/ba") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /ba must specify hex breakpoint above addr as next arg\n");
				exit(0);
			}
			opts.break_above = strtol(argv[i+1], NULL, 16);
			i++;handled=true;
		}

		if(sl==3 && strstr(argv[i],"/bs") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /bp must specify hex breakpoint addr as next arg\n");
				exit(0);
			}
		    opts.log_after_step = atoi(argv[i+1]);
			opts.verbosity_after = 3;
			i++;handled=true;
		}

		if(sl==4 && strstr(argv[i],"/laa") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /laa must specify a hex addr as next arg\n");
				exit(0);
			}
			opts.log_after_va = symbol2addr(argv[i+1]);
			if(opts.log_after_va == 0) opts.log_after_va = strtol(argv[i+1], NULL, 16);	
			i++;handled=true;
		}

		if(sl==6 && strstr(argv[i],"/redir") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /redir must specify IP:PORT as next arg\n");
				exit(0);
			}
		    opts.override.host = strdup(argv[i+1]);
			char *port;
			if (( port = strstr(opts.override.host, ":")) != NULL)
			{
				*port = '\0';
				port++;
				opts.override.port = atoi(port);

				if (*opts.override.host == '\0')
				{
					free(opts.override.host);
					opts.override.host = NULL;
				}

			}	
			i++;handled=true;
		}

		if(sl==4 && strstr(argv[i],"/las") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /las must specify a integer as next arg\n");
				exit(0);
			}
		    opts.log_after_step  = atoi(argv[i+1]);		
			i++;handled=true;
		}

		if(sl==2 && strstr(buf,"/e") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /e must specify err verbosity as next arg\n");
				exit(0);
			}
		    opts.verbosity_onerr = atoi(argv[i+1]);			
			i++;handled=true;
		}

		if(sl==7 && strstr(argv[i],"/disasm") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /disasm must specify #lines to disassemble as next arg\n");
				exit(0);
			}
		    opts.disasm_mode = atoi(argv[i+1]);			
			i++;handled=true;
		}

		if(sl==2 && strstr(buf,"/s") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /s must specify num of steps as next arg\n");
				exit(0);
			}
		    opts.steps = atoi(argv[i+1]);	
			i++;handled=true;
		}

		if(sl==2 && strstr(buf,"/t") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /t must specify delay in millisecs as next arg\n");
				exit(0);
			}
		    opts.time_delay = atoi(argv[i+1]);		
			i++;handled=true;
		}

		if(strstr(argv[i],"/va") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /va must specify 0xBase-0xSize as next arg\n");
				exit(0);
			}
		    char *ag = strdup(argv[i+1]);
			char *sz;
			uint32_t size=0;
			uint32_t base=0;
			if (( sz = strstr(ag, "-")) != NULL)
			{
				*sz = '\0';
				sz++;
				size = strtol(sz, NULL, 16);
				base = strtoul(ag, NULL, 16);
				printf("VirtualAlloc(base=%x, size=%x) (endsAt %x)\n", base, size, base+size);
				char* tmp = (char*)malloc(size);
				memset(tmp,0,size);
                emu_memory_write_block(mem, base, tmp, size);
				i++;handled=true;

			}else{
				printf("Invalid option /va must specify 0xBase-0xSize as next arg\n");
				exit(0);
			}
		}

		if( (sl==5 && strstr(argv[i],"/poke") > 0) || (sl==5 && strstr(argv[i],"/wint") > 0) ){
			if(i+1 >= argc){
				printf("Invalid option /wint must specify 0xBase-0xValue as next arg\n");
				exit(0);
			}
			if ( strstr(argv[i+1], "-") != NULL)
			{
				i++;handled=true; //validated here, but handed in post_parse_opts after loadsc()
			}else{
				printf("Invalid option /wint must specify 0xBase:0xValue as next arg\n");
				exit(0);
			}
		}

		if( (sl==6 && strstr(argv[i],"/spoke") > 0) || (sl==5 && strstr(argv[i],"/wstr") > 0) ){
			if(i+1 >= argc){
				printf("Invalid option /wstr must specify 0xBase-0xHexString or 0xBase-string as next arg\n");
				exit(0);
			}
			if ( strstr(argv[i+1], "-") != NULL)
			{
				i++;handled=true; //validated here, but handed in post_parse_opts after loadsc()
			}else{
				printf("Invalid option /wstr must specify 0xBase-0xHexString or 0xBase-string as next arg\n");
				exit(0);
			}
		}


		if(sl==4 && strstr(argv[i],"/raw") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /raw must specify 0xBase-fpath as next arg\n");
				exit(0);
			}
			if ( strstr(argv[i+1], "-") != NULL)
			{
				i++;handled=true; //validated here, but handed in post_parse_opts after loadsc()
			}else{
				printf("Invalid option /raw must specify 0xBase-fpath as next arg\n");
				exit(0);
			}
		}

		if( !handled ){
			start_color(myellow);
			printf("Unknown Option %s\n\n", argv[i]);
			end_color();
			exit(0);
		}

	}


}

char* strlower(char* input){
	char* alwaysWritable = (char*)malloc(strlen(input)+1);
	char* p = alwaysWritable;
	strcpy(alwaysWritable, input);
	while(*p){*p = tolower(*p);p++;}
	return alwaysWritable;
}

int HexToBin(char* input, int* output){

	int sl =  strlen(input) / 2;
	void *buf = malloc(sl+10);
    memset(buf,0,sl+10);

	char *lower = strlower(input);
	char *h = lower; /* this will walk through the hex string */
	unsigned char *b = (unsigned char*)buf; /* point inside the buffer */

	/* offset into this string is the numeric value */
	char xlate[] = "0123456789abcdef";

	for ( ; *h; h += 2, ++b) /* go by twos through the hex string */
	   *b = ((strchr(xlate, *h) - xlate) * 16) /* multiply leading digit by 16 */
		   + ((strchr(xlate, *(h+1)) - xlate));

	free(lower);
	*output = (int)buf;
	return sl;
		
}

void post_parse_opts(int argc, char* argv[] ){

	int i;
	int sl=0;
	char buf[5];
 
	for(i=1; i < argc; i++){
	
		sl = strlen(argv[i]);
		if( argv[i][0] == '-') argv[i][0] = '/'; //standardize
		 		
	    if(sl==4 && strstr(argv[i],"/raw") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /raw must specify 0xBase-fpath as next arg\n");
				exit(0);
			}
		    char *ag = strdup(argv[i+1]);
			char *sz;
			uint32_t base=0;
			if (( sz = strstr(ag, "-")) != NULL)
			{
				*sz = '\0';
				sz++;
				base = strtoul(ag, NULL, 16);
				loadraw_patch(base, sz);
				//printf("RawLoad Patch at base=%x, path=%s\n", opts.rawLoadBase, opts.rawLoad);
				i++;

			}else{
				printf("Invalid option /raw must specify 0xBase-fpath as next arg\n");
				exit(0);
			}
		}

		if( (sl==5 && strstr(argv[i],"/poke") > 0) || (sl==5 && strstr(argv[i],"/wint") > 0) ){
			if(i+1 >= argc){
				printf("Invalid option /wint must specify 0xBase-0xValue as next arg\n");
				exit(0);
			}
		    char *ag = strdup(argv[i+1]);
			char *sz;
			uint32_t value=0;
			uint32_t base=0;
			if (( sz = strstr(ag, "-")) != NULL)
			{
				*sz = '\0';
				sz++;
				value = strtoul(sz, NULL, 16);
				base = strtoul(ag, NULL, 16);
				//printf("Write Int base=%x, value=%x\n", base, value);
                emu_memory_write_dword(mem, base, value);
				i++;
			}else{
				printf("Invalid option /wint must specify 0xBase-0xValue as next arg\n");
				exit(0);
			}
		}

		if( (sl==6 && strstr(argv[i],"/spoke") > 0) || (sl==5 && strstr(argv[i],"/wstr") > 0) ){
			if(i+1 >= argc){
				printf("Invalid option /wstr must specify 0xBase-0xHexString or 0xBase-string as next arg\n");
				exit(0);
			}
		    char *ag = strdup(argv[i+1]);
			char *sz;
			void *embed;
			int embedLength=0;
			uint32_t base=0;
			if (( sz = strstr(ag, "-")) != NULL)
			{
				*sz = '\0';
				sz++;
				base = strtoul(ag, NULL, 16);

				if(sz[0] == '0' && sz[1] == 'x'){//its a hexstring
					sz+=2;
					embedLength = HexToBin(sz,  (int*)&embed);
					if(opts.bSwap) byteSwap((unsigned char*)embed,embedLength,"/wstr");
					if(opts.eSwap) endianSwap((unsigned char*)embed,embedLength,"/wstr");
					emu_memory_write_block(mem, base, embed, embedLength);
					free(embed);
				}else{ //its just a regular string to directly embed..
					embedLength = strlen(sz);
					emu_memory_write_block(mem, base, (void*)sz, embedLength);
				}
				//printf("Write String wrote %d bytes at base %x\n", embedLength, base);
				i++;
			}else{
				printf("Invalid option /wstr must specify 0xBase-0xHexString or 0xBase-string as next arg\n");
				exit(0);
			}
		}

	}

}

uint32_t stripChars(unsigned char* buf_in, int *output, uint32_t sz, char* chars){
	uint32_t out=0;
	int copy,c;
	unsigned char d;
	unsigned char* buf_out = (unsigned char*)malloc(sz);
	for(int i=0; i<sz; i++){
		copy = 1;
		c = 0;
		d = (unsigned char)buf_in[i];
		while(chars[c] != 0){
			if(d==chars[c]){ copy=0; break; } 
			c++;
		}
		if(copy) (unsigned char)buf_out[out++] = d;
	}
	
	*output = (int)buf_out;
	return out;
}

void loadsc(void){

	FILE *fp;

	if (opts.nofile || (opts.patch_file != NULL && opts.file_mode == false) ){ 
		//create a default allocation to cover any assumptions
		opts.scode = (unsigned char*) malloc(0x1000);
		opts.size = 0x1000;
		memset(opts.scode, 0, opts.size); 
		return;
	}
	
	fp = fopen(opts.sc_file, "rb");
	if(fp==0){
		start_color(myellow);
		printf("Failed to open file %s\n",opts.sc_file);
		end_color();
		exit(0);
	}
	opts.size = file_length(fp);
	opts.scode = (unsigned char*)malloc(opts.size+10); 
	memset(opts.scode, 0, opts.size+10);
	fread(opts.scode, 1, opts.size, fp);
	fclose(fp);
	if(!opts.automationRun) printf("Loaded %x bytes from file %s\n", opts.size, opts.sc_file);
	 
	if(opts.size==0){
		printf("No shellcode loaded must use either /f or /S options\n");
		show_help();
		return;
	}

	int tmp;
	int tmp2;
    int j=0;

	for(j=0; j<opts.size; j++){ //scan the buffer and ignore possible leading white space and quotes...
		unsigned char jj = opts.scode[j];
		if(jj != ' ' && jj != '\r' && jj != '\n' && jj != '"' && jj != '\t' && jj != '\'') break;
	}
	if(j >= opts.size-1) j = 0;

	if( (opts.scode[j] == '%' && opts.scode[j+1] == 'u') || (opts.scode[j] == '\\' && opts.scode[j+1] == 'u') ){
		start_color(colors::myellow);
		printf("Detected %%u encoding input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size, "\n\r\t,%u\";\' +\\"); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
		byteSwap(opts.scode, opts.size, "%u encoded"); 
	}else if(opts.scode[j] == '%' && opts.scode[j+3] == '%'){
		start_color(colors::myellow);
		printf("Detected %% hex input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size, "\n\r\t,%\";\' +"); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;		
	}else if(opts.scode[j] == '\\' && opts.scode[j+1] == 'x'){
		start_color(colors::myellow);
		printf("Detected \\x encoding input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size,"\n\r\t,\\x\";\' " ); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
	}else if(isxdigit(opts.scode[j]) && isxdigit(opts.scode[j+1]) && isxdigit(opts.scode[j+2]) && isxdigit(opts.scode[j+3]) ){
		bool allHex = true;
		unsigned char* tmp3 = (unsigned char*)SafeMalloc(opts.size);
		memcpy(tmp3,opts.scode, opts.size);
		uint32_t newSize = stripChars(tmp3, &tmp, opts.size,"\n\r\t,\\ \";\'" ); 
		unsigned char* c = (unsigned char*)tmp;
		for(int i=0;i < newSize; i++){
			if(!isxdigit(c[i])) allHex = false; 
			if(!allHex){
				//printf("failed at offset %x/%x value: %d memoffset %x\n", i,opts.size, c[i], &c[i]);
				break;
			}
		}
		free(tmp3);
		if(!allHex) return;
		start_color(colors::myellow);
		printf("Detected straight hex encoding input format converting...\n");
		end_color();
		opts.size = stripChars((unsigned char*)opts.scode, &tmp, opts.size,"\n\r\t,\\ \";\'" ); 
		free(opts.scode);
		opts.size = HexToBin((char*)tmp, &tmp2);
		opts.scode = (unsigned char*)tmp2;
	}

}


void min_window_size(void){
	CONSOLE_SCREEN_BUFFER_INFO sb;
	COORD maxb;
	BOOL ret = false;
	bool changed = false;
	SMALL_RECT da = {0, 0, 0, 0}; 
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    maxb = GetLargestConsoleWindowSize(hOut);
	GetConsoleScreenBufferInfo(hOut, &sb); 
	da = sb.srWindow;
	if(sb.srWindow.Right < 100 && maxb.X > 100){ da.Right = 100; changed = true;}
	if(sb.srWindow.Bottom < 40 && maxb.Y > 40){  da.Bottom = 40; changed = true;}
	maxb.X = da.Right + 1;
	maxb.Y = da.Bottom * 5;
	if(changed){
		ret = SetConsoleScreenBufferSize(hOut, maxb);
		//printf("Change buffer: %x\n", ret);
		ret = SetConsoleWindowInfo(hOut,TRUE,&da);
		//printf("SetInfo: %x\n", ret);
	}
}



int HookDetector(char* fxName){

	/*  typical api prolog 0-5, security apps will replace this with jmp xxxxxxxx
		which the hookers will detect, or sometimes just jump over always without checking..
		the jump without checking screws us up, so were compensating with this callback...
		7C801D7B   8BFF             MOV EDI,EDI
		7C801D7D   55               PUSH EBP
		7C801D7E   8BEC             MOV EBP,ESP
	*/

	start_color(colors::myellow); 
	printf("\tjmp %s+5 hook evasion code detected! trying to recover...\n", fxName);
	end_color();

	//if(strcmp(fxName,"LoadLibraryA") == 0){ //probably a pretty generic cleanup for x+5
		cpu->reg[esp] = cpu->reg[ebp];
		cpu->reg[ebp] = popd();
		return 1;
	//}

	/*printf("Unhandled...\n");
	exit(0);
	return 0;*/
	
}

char* isCmdFile(char* path){
	
	int sl = strlen(path);
	char* tmp = path + (sl-5);

	if( strstr(tmp, ".scmd") == 0 ) return 0;

	FILE *fp;	
	fp = fopen(path, "rb");

	if(fp==0){
		printf("Failed to open file %s\n",path);
		exit(0);
	}

	int size = file_length(fp);
	char* buf = (char*)malloc(size+10); 
	memset(buf,0xCC,size+10);
	fread(buf, 1,size, fp);
	fclose(fp);

	buf[size] = 0;
	buf[size+1] = 0;
	
	//allow command lines to be broken up into multiple lines. 
	//command portion of file terminates at first ; or # comment character found, (or eof if not)
	char* eol = buf;
	
	/*while(*eol){
		if(*eol=='\r') *eol=' ';
		if(*eol=='\n') *eol=' ';
		if(*eol=='\t') *eol=' ';
		if(*eol==';'){ *eol=0; break;}
		if(*eol=='#'){ *eol=0; break;}
		eol++;
	}
	char* ret = strdup(buf);
	free(buf);
	*/ 
	
	
	char* copyBuf = (char*)malloc(size+10); 
	memset(copyBuf,0xCC,size+10);
	char* t   = copyBuf;

	while(*eol){
		if(*eol!='\r' && *eol!='\n' && *eol!='\t'){
			if(*eol == ';' || *eol=='#'){ //comment encountered scan till eof or eol
				while(*eol){
					if(*eol=='\r' || *eol=='\n') break; 
					eol++;
				}
			}else{
				*t = *eol;
				t++;
			}
		}else{
			if( *(char*)(t-1) != ' '){ //it was a newline, if last char in copy buf is not a space add one..
				*t = ' ';
				t++;
			}
		}
		eol++;
	} 
	
	*t = 0;

	char* ret = strdup(copyBuf);
	free(buf);
	free(copyBuf); 

	return ret;

}

int main(int argc, char *argv[])
{
	int i=0;
	char cmd[500];
    char pth[500];

	disable_mm_logging = true;
	memset(&emm, 0, sizeof(emm));
	memset(&mallocs, 0 , sizeof(mallocs));
	memset(&opts,0,sizeof(struct run_time_options));
    
	min_window_size();
	SetConsoleCtrlHandler(ctrl_c_handler, TRUE); //http://msdn.microsoft.com/en-us/library/ms686016

	hCon = GetStdHandle( STD_INPUT_HANDLE );
	hConOut = GetStdHandle( STD_OUTPUT_HANDLE );

	DWORD old;
	GetConsoleMode(hCon, &old);
	old |= ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS ; //always enable this and leave it this way..
	orgt = old;
	old &= ~ENABLE_LINE_INPUT;
	//SetConsoleMode(hCon, old); //this fucks up Windows 7

	signal(SIGABRT,restore_terminal);
    signal(SIGTERM,restore_terminal);
	atexit(atexit_restore_terminal);

reinit:
	e = emu_new();
	cpu = emu_cpu_get(e);
	mem = emu_memory_get(e);
	env = emu_env_new(e);
	
	if(argc==2){ //check to see if its a drag and drop of file or folder on exe
		
		if( FileExists(argv[1]) ){
			char* cmdFile = isCmdFile(argv[1]);
			if(cmdFile !=0){
				char* scDbgDir = argv[0];
				if(!SetCurrentDirectory(GetParentFolder(argv[1]))) printf("error setting working directory for scmd file..%s\n", argv[1]);
				char* tmp = SafeMalloc(strlen(scDbgDir) + strlen(cmdFile) + 50);
				sprintf( (char*)tmp, "cmd /k %s %s", scDbgDir, cmdFile);
				//printf("scmd file found, running command line: %s\n\n", cmdFile);
				printf("Running commands from scmd file: %s\n",argv[1]);
				system(tmp);
				exit(0);
			}else{
				if(!SetCurrentDirectory(GetParentFolder(argv[0]))) printf("error setting working directory for drag and drop mode..exe=%s\n", argv[0]);
				GetShortPathName(argv[1], pth, 500);
				sprintf( (char*)cmd, "cmd /k scdbg.exe -f %s", pth);
				system(cmd);
				exit(0);
			}
		}
	
		if( FolderExists(argv[1]) ){
			if(!SetCurrentDirectory(GetParentFolder(argv[0]))) printf("error setting working directory for drag and drop mode..exe=%s\n", argv[0]);
			GetShortPathName(argv[1], pth, 500);
			sprintf( (char*)cmd, "cmd /k scdbg.exe -dir %s", pth);
			system(cmd);
			exit(0);
		}
	}

	if(opts.opts_parsed == 0) parse_opts(argc, argv); //this must happen AFTER emu_env_new for -bp apiname lookup

	//emu_log_level_set( emu_logging_get(e),  EMU_LOG_DEBUG);

	if ( env == 0 ){ printf("%s\n%s\n", emu_strerror(e), strerror(emu_errno(e))); exit(-1);}

	if(opts.scan_dir != NULL){
		HandleDirMode(opts.scan_dir);
		exit(0);
	}

	if(!opts.nofile){ //nofile is if they use -raw or -spoke to embed the code
		if(opts.file_mode == false && opts.patch_file == NULL)	show_help();
	}

	loadsc();	
	
	if(!opts.nofile){ 
		if(opts.bSwap) byteSwap(opts.scode,opts.size, "main");
		if(opts.eSwap) endianSwap(opts.scode,opts.size, "main");
	}

	if(opts.convert_outPath != 0){
		start_color(colors::myellow);
		printf("Dumping converted buffer to file %s\n", opts.convert_outPath);
		FILE* fp = fopen(opts.convert_outPath, "wb");
		if(!fp){printf("Failed.."); exit(0);};
		fwrite(opts.scode, 1, opts.size, fp);
		fclose(fp);
		printf("File written successfully...\n");
		end_color();
		exit(0);
	}

	init_emu();

	post_parse_opts(argc,argv); //this allows multiple pokes and raw patch loads 
	//if(opts.rawLoadBase!=0) loadraw_patch();
	if(opts.patch_file != NULL) LoadPatch(opts.patch_file);

	if(opts.getpc_mode){
		
		uint32_t orgStartOffset = opts.offset; //let them start -findsc where they want...

		opts.offset = find_sc();
		
		if( opts.offset != -1){
				opts.getpc_mode = false;
				goto reinit; //this gives us a full reinitilization of the whole envirnoment for the run..had a weird bug otherwise..
		}

		printf("\nTrying -bswap...\n");
		byteSwap(opts.scode, opts.size, "-findsc");
		opts.offset = orgStartOffset;

		opts.offset = find_sc();

		if( opts.offset != -1){
			opts.bSwap = true;
			opts.getpc_mode = false;
			goto reinit; //full reinitilization of the whole envirnoment 
		}

		printf("\nTrying -eswap...\n");
		byteSwap(opts.scode, opts.size, ""); //back to normal...
		endianSwap(opts.scode,opts.size, "-findsc");
        opts.offset = orgStartOffset;

		opts.offset = find_sc();

		if( opts.offset != -1){
			opts.eSwap = true;
			opts.getpc_mode = false;
			goto reinit; //full reinitilization of the whole envirnoment 
		}

		return -1;

	}

	if( opts.automationRun ){
		opts.show_hexdumps = false;
		opts.no_color = true;
		opts.verbose = 0;
	}

	if( opts.offset > opts.baseAddress ){
		start_color(myellow);
		printf("/foff looks like a VirtualAddress adjusting to file offset...\n");
		end_color();
		opts.offset -= opts.baseAddress;
	}

	if(opts.cmdline != NULL){
		printf("Using Command line: %s\n", opts.cmdline);
	}

	if(opts.interactive_hooks==1){
		WORD wVersionRequested;
		WSADATA wsaData;
        wVersionRequested = MAKEWORD(2, 2);
	    WSAStartup(wVersionRequested, &wsaData);
	}

	//---- mem_monitor init - always started now to generate reports.. mm & mdll still shows more specifics in log output
	i=0;
	if(opts.mem_monitor || opts.report ){
		if(!opts.automationRun) if(opts.mem_monitor) printf("Memory monitor enabled..\n"); 
		emu_memory_set_access_monitor((uint32_t)mm_hook);
		while(mm_points[i].address != 0){
			emu_memory_add_monitor_point(mm_points[i++].address);
		}
	}

	emu_env_w32_set_hookDetect_monitor((uint32_t)HookDetector);
    emu_env_w32_set_syscall_monitor((uint32_t)SysCall_Handler);

	if(opts.mem_monitor || opts.report || opts.mem_monitor_dlls){
 		if(!opts.automationRun) if(opts.mem_monitor_dlls) printf("Memory monitor for dlls enabled..\n");
		emu_memory_set_range_access_monitor((uint32_t)mm_range_callback);
		i=0;
		while(mm_ranges[i].start_at != 0){
			emu_memory_add_monitor_range(mm_ranges[i].id, mm_ranges[i].start_at, mm_ranges[i].end_at);
			i++;
		}
	}
	
	if(opts.report){ //monitor writes to main code mem.
		emu_memory_add_monitor_range(0x66, opts.baseAddress, opts.baseAddress + opts.size); 
    }
	//---- end memory monitor init 

	if(!opts.automationRun)printf("Initialization Complete..\n");

	if(opts.adjust_getfsize != 0) printf("Adjusting GetFileSize by %d\n", opts.adjust_getfsize);
	
	if(opts.hexdump_file == 1){
		hexdump_color = true; //highlights possible start addresses (90,E8,E9)
		if(opts.offset >= opts.size ) opts.offset = 0;
		if(!opts.automationRun) if(opts.offset > 0) printf("Starting at offset %x\n", opts.offset);
		if(!opts.automationRun) real_hexdump(opts.scode+opts.offset, opts.size-opts.offset,0,false);
		return 0;
	}

	if(opts.disasm_mode > 0){
		if(opts.offset >= opts.size ) opts.offset = 0;
		if(opts.offset > 0) printf("Starting at offset %x\n", opts.offset);
		start_color(mgreen);
		disasm_block(opts.baseAddress+opts.offset, opts.disasm_mode);
		end_color();
		return 0;
	}

	if( opts.override.host != NULL){
		printf("Override connect host active %s\n", opts.override.host);
	}

	if( opts.override.port != 0){
		printf("Override connect port active %d\n", opts.override.port);
	}

	if(opts.log_after_va  > 0 || opts.log_after_step > 0){
		
		if(opts.verbosity_after == 0) opts.verbosity_after =1;
		if(opts.verbose > opts.verbosity_after) opts.verbosity_after = opts.verbose ;
		opts.verbose = 0;
		
		if(opts.log_after_va  > 0){
			printf("Will commence logging at eip 0x%x verbosity: %i\n", opts.log_after_va , opts.verbosity_after );
		}else{
			printf("Will commence logging at step %d verbosity: %i\n", opts.log_after_step , opts.verbosity_after );
		}

	}

	if(opts.dump_mode){
		if(opts.file_mode == false){
			printf("Dump mode can not run when only using a patch file.\n");
			opts.dump_mode = false;
		}else{
			if(!opts.automationRun) printf("Dump mode Active...\n");
		}
	}
		
	if(opts.interactive_hooks){
		start_color(myellow);
		if(!opts.automationRun) printf("Interactive Hooks enabled\n");
		end_color();
	}

	if(!opts.automationRun) printf("Max Steps: %d\n", opts.steps);
	if(!opts.automationRun) printf("Using base offset: 0x%x\n", opts.baseAddress);
	if(!opts.automationRun) if(opts.verbose>0) printf("Verbosity: %i\n", opts.verbose);

	if(opts.rop){
		cpu->reg[esp] = opts.baseAddress+opts.offset; //this is where they think the rop chain starts...
		cpu->reg[ebp] = opts.baseAddress+opts.size;
		opts.offset = opts.size + 1; //we are going to start the actual execution at a ret of our own...
		emu_memory_write_byte(mem, opts.baseAddress + opts.offset, 0xC3); //write a ret as first instruction after loaded shellcode buffer. 
	}

	if(opts.offset > 0 && !opts.automationRun){
		if(opts.rop) printf("ROP Mode: First return address set to be %x\n", cpu->reg[esp]); 
		 else printf("Execution starts at file offset %x\n", opts.offset);
		start_color(mgreen);
		if(opts.rop){
			uint32_t bytes_read;
			nl();
			printf("VirtAddress | Return Address | Stack Position\n");
			printf("---------------------------------------------\n");
			for(i=0;i<=5;i++){
				if(emu_memory_read_dword(mem, cpu->reg[esp]+(i*4), &bytes_read) == -1) break;
				printf("%08x\t %08x\t [esp+%x]\n", cpu->reg[esp]+(i*4), bytes_read, i*4);  
			}
		}else{
			disasm_block(opts.baseAddress+opts.offset, 5);
		}
		end_color();
		nl(); 
	}

	nl();
	run_sc();

	if( IsDebuggerPresent() ) getch();
	return opts.cur_step;
	 
}

void loadraw_patch(uint32_t base, char* fpath){

	FILE *fp;

	if (fpath == NULL) return;
	
	fp = fopen(fpath, "rb");
	if(fp==0){
		start_color(myellow);
		printf("RawLoad Failed to open file %s\n",fpath);
		end_color();
		exit(0);
	}

	uint32_t size = file_length(fp);
	unsigned char* buf = (unsigned char*)SafeMalloc(size); 
	fread(buf, 1, size, fp);
	fclose(fp);

	printf("RawLoad 0x%x bytes at 0x%x from file %s\n", size,base,fpath);
	 
	emu_memory_write_block(mem, base, buf, size);
	free(buf);

}

void LoadPatch(char* fpath){
	
	patch p;
	size_t r = sizeof(patch);
	long curpos=0;
	int i = 0;
	uint32_t regx;
	char *buf = 0;
	char addr[12];
	uint32_t memAddress=0;

	//patch file format is 8 longs (registers) followed by an array of patch structs 
	//terminated by empty struct at end. field dataOffset points
	//to the raw start file offset of the patch file for the data to load.

	FILE *f = fopen(fpath, "rb");
	if( f == 0 ){
		printf("Failed to open patch file: %s\n", fpath);
		return;
	}

	printf("Loading patch file %s\n", fpath);

	start_color(mgreen);
	for(i=0;i<8;i++){
		fread(&regs[i],4,1,f); //load registers
		if(cpu!=0) cpu->reg[i] = regs[i];
		printf("%s=%-8x  ", regm[i], regs[i]);
		if( i==3 || i==7) nl();
	}
	end_color();
	
	i=0;
	r = fread(&p, sizeof(struct patch),1,f);

	while( p.dataOffset > 0 ){
		curpos = ftell(f);
		p.comment[15] = 0; 

		if( fseek(f, p.dataOffset, SEEK_SET) != 0 ){
			printf("Patch: %d  - Error seeking data offset %x cmt=%s\n", i, p.dataOffset, p.comment );
			break;
		}

		buf = (char*)malloc(p.dataSize); 
		r = fread(buf, 1, p.dataSize, f);
		if( r != p.dataSize ){
			printf("patch %d - failed to read full size %x readsz=%x cmt=%s\n", i, p.dataSize, r, p.comment);
			break;
		}

		memset(addr, 0, 12);
		memcpy(addr, p.memAddress, 8); //no trailing null to keep each entry at 16 bytes
		memAddress = strtol(addr, NULL, 16);	

		emu_memory_write_block(mem, memAddress, buf, p.dataSize);
		printf("Applied patch %d va=%x sz=%x cmt=%s\n", i, memAddress, p.dataSize, p.comment ); 
		free(buf);

		fseek(f, curpos, SEEK_SET);
		r = fread(&p, sizeof(struct patch),1,f); //load next patch
		i++;
	}

	fclose(f);

}

void HandleDirMode(char* folder){

	if( !FolderExists(folder) ){
		printf("Could not find folder %s\n", folder);
		return;
	}

	WIN32_FIND_DATA FileData;
	HANDLE hSearch;
	char cmdline[1000];
	char shortname[500];
	char longPath[500];
	char* divider = "\n----------------------------------------------------------\n";
	int i=0;

	if(strlen(folder) > 300) return;

	if(opts.report){
		sprintf(cmdline, "%s\\report.txt", folder);
		if(FileExists(cmdline)) unlink(cmdline);
	}

	sprintf(cmdline, "%s\\%s", folder, "*.sc");

	hSearch = FindFirstFile(cmdline, &FileData); 
	if (hSearch == INVALID_HANDLE_VALUE){ 
	    printf("No .sc files found in %s\n",folder); 
	    return;
	} 
	
	system("cls");
	printf("\n\n  Processing all sc files in %s\n\n", folder);
	printf("  Min steps: %d\n\n", opts.min_steps);

	while(1){ 
		printf("  %s", FileData.cFileName); 
		sprintf(cmdline, "%s\\%s", folder, FileData.cFileName);
		GetShortPathName(cmdline, (char*)&shortname, 500);
		
		sprintf(cmdline, "scdbg -auto -f %s ", shortname);
		if(opts.verbose > 0) strcat(cmdline, "-r");
		if(opts.steps == -1) strcat(cmdline, "-u");

		if(opts.report) 
			sprintf(cmdline+strlen(cmdline), " >> %s\\report.txt", folder);
		else
			sprintf(cmdline+strlen(cmdline), " > %s.txt", shortname);

		int retval = system(cmdline);
		printf("\tSteps: %-8x", retval);

		if( retval < opts.min_steps ){
			printf(" -findsc:");

			sprintf(cmdline, "scdbg -auto -findsc -f %s -min %d ", shortname, opts.min_steps);
			if(opts.verbose > 0) strcat(cmdline, "-r");
			if(opts.steps == -1) strcat(cmdline, "-u");

			if(opts.report) 
				sprintf(cmdline+strlen(cmdline), " >> %s\\report.txt", folder);
			else
				sprintf(cmdline+strlen(cmdline), " > %s.txt", shortname);

			retval = system(cmdline);
			printf(" %x", retval);
		}
		
		//redundant now that -findsc supports -bswap and -eswap on its own..
		/*if( retval < opts.min_steps){
			printf("\t-bSwap:");

			sprintf(cmdline, "scdbg -auto -findsc -bswap -f %s -min %d ", shortname, opts.min_steps);
			if(opts.verbose > 0) strcat(cmdline, "-r");
			if(opts.steps == -1) strcat(cmdline, "-u");

			if(opts.report) 
				sprintf(cmdline+strlen(cmdline), " >> %s\\report.txt", folder);
			else
				sprintf(cmdline+strlen(cmdline), " > %s.txt", shortname);

			retval = system(cmdline);
			printf(" %x", retval);
		}

		if( retval < opts.min_steps){
			printf("\t-eswap:");

			sprintf(cmdline, "scdbg -auto -findsc -eswap -f %s -min %d ", shortname, opts.min_steps);
			if(opts.verbose > 0) strcat(cmdline, "-r");
			if(opts.steps == -1) strcat(cmdline, "-u");

			if(opts.report) 
				sprintf(cmdline+strlen(cmdline), " >> %s\\report.txt", folder);
			else
				sprintf(cmdline+strlen(cmdline), " > %s.txt", shortname);

			retval = system(cmdline);
			printf(" %x", retval);
		}*/

		if( !opts.report ){ //restore the file name from shortpath 
			strcat(shortname, ".txt");
			sprintf(longPath, "%s\\%s.txt", folder, FileData.cFileName);
			retval = rename(shortname, longPath );
		}
		
		nl();
		i++;
		if (!FindNextFile(hSearch, &FileData)) break;
	}

	printf("\n  Found %d files\n\n", i);
	FindClose(hSearch);
}














