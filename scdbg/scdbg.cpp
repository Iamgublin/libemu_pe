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
	I have yet to see. its a dirty hack, but in practice (so far) its working just fine...

	TODO: 

		  fix peb module order..(specific legit order for each list)

		  CreateFileMapping/MapViewofFile - figure out how to make work...

		  for hooks with lots of args, (and needed for debugging) use opts.verbose to
		  select which to use (simple vrs debug)

		  InMemoryOrderModuleList 2nd dll supposed to be k32 ? 

		  update the mdll ranges for new dlls

		  if you let a dll load on demand, you have to set the hooks as that dll loads?

		  implement guts of ZwQueryVirtualMemory hook if warrented (probably not lots of work)

	      it would be nice to be able to load arbitrary dlls on cmdline would need:
		      pe parsing to load and parse dll format 
			  either need to call some export before emu_env_w32_new, or cache last peb pointers
			  used, and load after the fact..maybe could eliminate all internal dlls then?

		  add string deref for pointers in stack dump, deref regs and dword dump?
		  opcode 2F could use supported 

		  [0] should return memory not mapped error...why doesnt it? (-1 too)
			answer: any call to write memory created memory if it didnt exist.
			        so only mem reads of non-existant addresses triggered not mapped
					errors. I put a very basic restriction in so no address < 0x1000
					will do this..this will support shellcode which expect to trigger errors
					with a write to 0 or the execute of code which is all 0000 add [eax], al
					now leads to immediate crash as expected. (and confusing if it doesnt!)

		  how/why/where are loadlibraryA opcodes being written to memory?
		     answer: looks like entire .text section with imports was included.
			         (I have just been using the mz/pe header and the export table when i add a dll)


*/


# include <stdlib.h>
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

#include "userhooks.h"
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
};

int malloc_cnt=0;
struct m_allocs mallocs[21];

struct emm_mode emm; //extended memory monitor
struct run_time_options opts;
struct emu *e = 0;           //one global object 
struct emu_cpu *cpu = 0;
struct emu_memory *mem = 0;
struct emu_env *env = 0;
//struct nanny *na = 0;
	
void debugCPU(struct emu *e, bool showdisasm);
int fulllookupAddress(int eip, char* buf255);
void init_emu(void);
void disasm_addr_simple(int);
void LoadPatch(char* fpath);
void HandleDirMode(char* folder);


uint32_t FS_SEGMENT_DEFAULT_OFFSET = 0x7ffdf000;
int CODE_OFFSET = 0x00401000;
int ctrl_c_count=0;
uint32_t last_good_eip=0;
uint32_t previous_eip=0;
bool disable_mm_logging = false;
int lastExceptionHandler=0;
int exception_count=0;
bool in_repeat = false;
int mdll_last_read_eip=0;
int mdll_last_read_addr=0;

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
	{6, "wininet",  0x3d930000+0x1844+0x1D4A+0x1, 0x3d930000+0xD0750},

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

//enum Color { DARKBLUE = 1, DARKGREEN=2, DARKTEAL=3, DARKRED=4, 
//			   DARKPINK=5, DARKYELLOW=6, GRAY=7, DARKGRAY=8, 
//             BLUE=9, GREEN=10, TEAL=11, RED=12, PINK=13, YELLOW=14, WHITE=15 };

enum colors{ mwhite=15, mgreen=10, mred=12, myellow=14, mblue=9, mpurple=5 };

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
	while ( env->env.win->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls]; 
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
	while ( env->env.win->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls]; 
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
	while ( env->env.win->loaded_dlls[numdlls] != 0 ){
		 
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls];
		
		if(dllmap_mode){
			printf("\t%-8s Dll mapped at %x - %x\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize);
		}
		else{
			if(strcmp(dll->dllname, symbol)==0){
				printf("\t%s Dll mapped at %x - %x\n", dll->dllname, dll->baseaddr , dll->baseaddr+dll->imagesize);
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

	while ( env->env.win->loaded_dlls[numdlls] != 0 )
	{
		if ( eip == env->env.win->loaded_dlls[numdlls]->baseaddr ){
			
			if(eip == 0x7C800000)
				strcpy(buf255, "Kernel32 Base Address");
			else
				sprintf(buf255, "%s Base Address", env->env.win->loaded_dlls[numdlls]->dllname );
			
			return 1;
		}
		else if ( eip > env->env.win->loaded_dlls[numdlls]->baseaddr && 
			      eip < env->env.win->loaded_dlls[numdlls]->baseaddr + 
				            env->env.win->loaded_dlls[numdlls]->imagesize )
		{
			struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[numdlls];
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

bool was_packed(void){
	unsigned char* tmp; int ii;
	tmp = (unsigned char*)malloc(opts.size);
	if(emu_memory_read_block(mem, CODE_OFFSET, tmp,  opts.size) == -1) return false;
	for(ii=0;ii<opts.size;ii++){
		if(opts.scode[ii] != tmp[ii]) break;
	}
	return ii < opts.size ? true : false;
}

void do_memdump(void){
	
	unsigned char* tmp ;
	char* tmp_path;
	int ii;
	FILE *fp;

	printf("Primary memory: Reading 0x%x bytes from 0x%x\n", opts.size, CODE_OFFSET);
	tmp = (unsigned char*)malloc(opts.size);
   	tmp_path = (char*)malloc( strlen(opts.sc_file) + 50);

	if(emu_memory_read_block(mem, CODE_OFFSET, tmp,  opts.size) == -1){
		printf("ReadBlock failed!\n");
	}else{
   	 
		printf("Scanning for changes...\n");
		for(ii=0;ii<opts.size;ii++){
			if(opts.scode[ii] != tmp[ii]) break;
		}

		if(ii < opts.size){
			strcpy(tmp_path, opts.sc_file);
			sprintf(tmp_path,"%s.unpack",tmp_path);

			start_color(myellow);
			printf("Change found at %i dumping to %s\n",ii,tmp_path);
		
			fp = fopen(tmp_path, "wb");
			if(fp==0){
				printf("Failed to create file\n");
			}else{
				fwrite(tmp, 1, opts.size, fp);
				fclose(fp);
				printf("Data dumped successfully to disk");
			}
			end_color();
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
   			 
				strcpy(tmp_path, opts.sc_file);
				sprintf(tmp_path,"%s.alloc_0x%x",tmp_path, mallocs[ii].base);
			
				fp = fopen(tmp_path, "wb");
				if(fp==0){
					printf("Failed to create file\n");
				}else{
					fwrite(tmp, 1, mallocs[ii].size, fp);
					fclose(fp);
					printf("Alloc %x (%x bytes) dumped successfully to disk as %s\n", mallocs[ii].base, mallocs[ii].size, tmp_path);
				}
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

	printf("Display rows: %x\n", display_rows);

	if(!hexonly) printf(nl);
	
	if(offset >=0){
		printf("        0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n");
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
				if( display_rows > 0 && displayed_lines == display_rows){
					displayed_lines = 0;
					printf("-- More --");
					char qq = getch();
					if(qq == 'q') break;
					printf("\n");
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

void disasm_addr_simple(int va){
	char disasm[200];
	emu_disasm_addr(cpu, va, disasm);
	start_color(mgreen);
	printf("%x   %s\n", va, disasm);
	end_color();
}
	
int disasm_addr(struct emu *e, int va){  //arbitrary offset
	
	int instr_len =0;
	char disasm[200];
	struct emu_cpu *cpu = emu_cpu_get(e);
	
	uint32_t retAddr=0;
	uint32_t m_eip     = va;
	instr_len = emu_disasm_addr(cpu, m_eip, disasm); 
	
	int foffset = m_eip - CODE_OFFSET;
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

	for(i = -16; i<=24;i+=4){
		emu_memory_read_dword(mem,curesp+i,&mretval);
		fulllookupAddress(mretval, (char*)&buf);
		if(i<0){
			printf("[ESP - %-2x] = %08x\t%s\n", abs(i), mretval, buf);
		}else if(i==0){
			printf("[ESP --> ] = %08x\t%s\n", mretval, buf);
		}else{
			printf("[ESP + %-2x] = %08x\t%s\n", i, mretval, buf);
		}
	}
	
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
			"\to - step over\n" 
			"\t.lp - lookup - get symbol for address\n"  
			"\t.pl - reverse lookup - get address for symbol\n"  
			"\t.seh - shows current value at fs[0]\n"
			"\t.reg - manually set register value\n"
			"\t.poke1 - write a single byte to memory\n"
			"\t.poke4 - write a 4 byte value to memory\n"
			"\t.savemem - saves a memdump of specified range to file\n"
			"\tq - quit\n\n"
		  );
}

void interactive_command(struct emu *e){

	printf("\n");
    
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

	while(1){

		if( (c >= 'a' || c==0) && c != 0x7e) printf("dbg> "); //stop arrow and function key weirdness...
		if( c == '.') printf("dbg> ");

		c = getch();

		if(c=='q'){ opts.steps =0; break; }
		if(c=='g'){ opts.verbose =0; break; }
		if(c=='s' || c== 0x0A) break;
		if(c=='?' || c=='h') show_debugshell_help();
		if(c=='f') deref_regs();
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
			if(previous_eip < CODE_OFFSET || previous_eip > (CODE_OFFSET + opts.size)) previous_eip = last_good_eip;
			if(previous_eip < CODE_OFFSET || previous_eip > (CODE_OFFSET + opts.size) ) previous_eip = cpu->eip ;
			if(previous_eip >= CODE_OFFSET && previous_eip <= (CODE_OFFSET + opts.size) ){
				opts.step_over_bp = previous_eip + get_instr_length(previous_eip);
				opts.verbose = 0;
				/*start_color(myellow);
				printf("Step over will break at %x\n", opts.step_over_bp);
				end_color();*/
				break;
			}
			else{
				printf("Could not determine next address? lgip = %x, cureip=%x\n", last_good_eip , cpu->eip);
			}
		}

		if(c=='.'){  //dot commands
			i = read_string("",tmp);
			if(i>0){
				if(strcmp(tmp,"seh")==0) show_seh();
				if(strcmp(tmp,"savemem")==0) savemem();
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

		if(c=='w'){
			base = read_hex("Enter hex base to dump", tmp);
			size = read_hex("Enter words to dump",tmp);
			int rel = read_int("Offset mode 1,2,-1,-2 (abs/rel/-abs/-rel)", tmp);			
			if(rel==0) rel = 1;

			if( rel < 1 ){
				for(i=base-size;i<=base;i+=4){
					if(emu_memory_read_dword(mem, i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base );
						break;
					}else{
						fulllookupAddress(bytes_read,(char*)&lookup);
						if(rel == -2){
							printf("[x - %-2x]\t%08x\t%s\n", (base-i), bytes_read, lookup );
						}else{
							printf("%08x\t%08x\t%s\n", i, bytes_read, lookup);
						}
					}
				}
			}else{
				for(i=0;i<=size;i+=4){
					if(emu_memory_read_dword(mem, base+i, &bytes_read) == -1){
						printf("Memory read of %x failed \n", base+i );
						break;
					}else{
						fulllookupAddress(bytes_read,(char*)&lookup);
						if(rel == 2){
							printf("[x + %-2x]\t%08x\t%s\n", i, bytes_read, lookup );
						}else{
							printf("%08x\t%08x\t%s\n", base+i, bytes_read, lookup);
						}
					}
				}
			}

		}

	}

	printf("\n");
	free(tmp);
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

	emu_env_w32_export_new_hook(env, "GetModuleHandleA", new_user_hook_GetModuleHandleA, NULL);
	emu_env_w32_export_new_hook(env, "GlobalAlloc", new_user_hook_GlobalAlloc, NULL);
	emu_env_w32_export_new_hook(env, "CreateProcessInternalA", new_user_hook_CreateProcessInternalA, NULL);
	emu_env_w32_export_new_hook(env, "MessageBoxA", new_user_hook_MessageBoxA, NULL);
	emu_env_w32_export_new_hook(env, "ShellExecuteA", new_user_hook_ShellExecuteA, NULL);
	emu_env_w32_export_new_hook(env, "SHGetSpecialFolderPathA", new_user_hook_SHGetSpecialFolderPathA, NULL);
	emu_env_w32_export_new_hook(env, "MapViewOfFile", new_user_hook_MapViewOfFile, NULL);
	emu_env_w32_export_new_hook(env, "URLDownloadToCacheFileA", new_user_hook_URLDownloadToCacheFileA, NULL);
	emu_env_w32_export_new_hook(env, "system", new_user_hook_system, NULL);
	emu_env_w32_export_new_hook(env, "VirtualAlloc", new_user_hook_VirtualAlloc, NULL);
	emu_env_w32_export_new_hook(env, "VirtualProtectEx", new_user_hook_VirtualProtectEx, NULL);
	emu_env_w32_export_new_hook(env, "SetFilePointer", new_user_hook_SetFilePointer, NULL);
	emu_env_w32_export_new_hook(env, "ReadFile", new_user_hook_ReadFile, NULL);
	emu_env_w32_export_new_hook(env, "strstr", new_user_hook_strstr, NULL);
	emu_env_w32_export_new_hook(env, "strtoul", new_user_hook_strtoul, NULL);
	emu_env_w32_export_new_hook(env, "GetTempFileNameA", new_user_hook_GetTempFileNameA, NULL);
	emu_env_w32_export_new_hook(env, "LoadLibraryExA", new_user_hook_LoadLibrary, NULL);
	emu_env_w32_export_new_hook(env, "LoadLibraryA", new_user_hook_LoadLibrary, NULL);
	emu_env_w32_export_new_hook(env, "GetModuleFileNameA", new_user_hook_GetModuleFileNameA, NULL);
	emu_env_w32_export_new_hook(env, "DialogBoxIndirectParamA", new_user_hook_DialogBoxIndirectParamA, NULL);
	emu_env_w32_export_new_hook(env, "ZwQueryVirtualMemory", new_user_hook_ZwQueryVirtualMemory, NULL);
	emu_env_w32_export_new_hook(env, "GetEnvironmentVariableA", new_user_hook_GetEnvironmentVariableA, NULL);
	emu_env_w32_export_new_hook(env, "VirtualAllocEx", new_user_hook_VirtualAllocEx, NULL);
	emu_env_w32_export_new_hook(env, "WriteProcessMemory", new_user_hook_WriteProcessMemory, NULL);
	emu_env_w32_export_new_hook(env, "CreateRemoteThread", new_user_hook_CreateRemoteThread, NULL);
	emu_env_w32_export_new_hook(env, "MultiByteToWideChar", new_user_hook_MultiByteToWideChar, NULL);
	emu_env_w32_export_new_hook(env, "URLDownloadToCacheFileW", new_user_hook_URLDownloadToCacheFileA, NULL);
	emu_env_w32_export_new_hook(env, "CreateFileW", new_user_hook_CreateFileW, NULL);
	emu_env_w32_export_new_hook(env, "CreateProcessInternalW", new_user_hook_CreateProcessInternalA, NULL);
	

	//-----handled by the generic stub
	emu_env_w32_export_new_hook(env, "InternetReadFile", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "ZwTerminateProcess", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "ZwTerminateThread", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "TerminateThread", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "FreeLibrary", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "GlobalFree", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "GetCurrentProcess", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "TerminateProcess", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "CreateThread", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "GetSystemTime", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "RtlDestroyEnvironment", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "RevertToSelf", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "RtlExitUserThread", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "FlushViewOfFile", new_user_hook_GenericStub, NULL);
    emu_env_w32_export_new_hook(env, "UnmapViewOfFile", new_user_hook_GenericStub, NULL);
	emu_env_w32_export_new_hook(env, "FindClose", new_user_hook_GenericStub, NULL);

	//-----handled by the generic stub 2 string
	emu_env_w32_export_new_hook(env, "InternetOpenA", new_user_hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "InternetOpenUrlA", new_user_hook_GenericStub2String, NULL);
	emu_env_w32_export_new_hook(env, "SHRegGetBoolUSValueA", new_user_hook_GenericStub2String, NULL);

	emu_env_w32_export_new_hook_ordial(env, "shdocvw", 0x65, new_user_hook_shdocvw65);

	//conversions from dll
    #define ADDHOOK(name) emu_env_w32_export_new_hook(env, #name, new_user_hook_##name, NULL);

	ADDHOOK(URLDownloadToFileA);
	ADDHOOK(execv);
	ADDHOOK(fclose);
	ADDHOOK(fopen);
	ADDHOOK(fwrite);
	ADDHOOK(_lcreat);
	ADDHOOK(_lclose);
	ADDHOOK(_lwrite);
	ADDHOOK(_hwrite);
	ADDHOOK(GetTickCount);
	ADDHOOK(GetTempPathA);
	ADDHOOK(WinExec);
	ADDHOOK(Sleep);
	ADDHOOK(DeleteFileA);
	ADDHOOK(ExitProcess);
	emu_env_w32_export_new_hook(env, "ExitThread", new_user_hook_ExitProcess, NULL);
	ADDHOOK(CloseHandle);
	ADDHOOK(CreateFileA);
	ADDHOOK(CreateProcessA);
	ADDHOOK(GetVersion);
	ADDHOOK(GetProcAddress);
	ADDHOOK(GetSystemDirectoryA);
	ADDHOOK(malloc);
	ADDHOOK(memset);
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
	ADDHOOK(GetFileSize);
	ADDHOOK(EnumWindows);
	ADDHOOK(GetClassNameA);
	ADDHOOK(fread);


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
		printf("\n%x\tException caught SEH=0x%x (seh foffset:%x)\n", last_good_eip, seh_handler, seh_handler - CODE_OFFSET);
		
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

int mini_run(int limit){

	int steps=0;

	while (emu_cpu_parse(cpu) == 0)
	{
		if ( emu_cpu_step(cpu) != 0 ) break;
        if(steps >= limit) break;
		if(!cpu->repeat_current_instr) steps++;
	}
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
	
	int i, ret, s, j ;    
	int limit = 250000;
    char buf[20];
    int last_offset= -2, last_step_cnt=0;
	struct result results[41];
	struct result sorted[11];
	int regs[] = {0,0,0,0,0x12fe00,0x12fff0,0,0};
	char buf255[255];

	j=0;
	regs[0]=0;

	memset(&results,0,sizeof(struct result)*41);
	int r_cnt = -1;

	for(i=0; i < opts.size ; i++){

		emu_memory_write_block(mem, CODE_OFFSET, opts.scode,  opts.size);
		for (j=0;j<8;j++) cpu->reg[j] = regs[j];

		if( opts.scode[i] != 0 ){
			cpu->eip = CODE_OFFSET + i;
			s = mini_run(limit);
			if(s > 100 && cpu->eip > (CODE_OFFSET + i + 100) ){
				if(last_step_cnt >= s && (last_offset+1) == i ){ //try not to spam
					last_offset++;
				}else{
					r_cnt++;
					if(r_cnt > 40) break;
					results[r_cnt].final_eip = cpu->eip;
					results[r_cnt].offset = i;
					results[r_cnt].steps  = s;
					results[r_cnt].org_i  = i;
					last_offset = i;
					last_step_cnt = s;
				}
			}
		}


	}

	if( r_cnt == -1 ){
		printf("No shellcode detected..\n");
		return -1;
	}

	//let them choose from the top 10
	for(i=0;i<10;i++){
		s = find_max(results,40);
		if(s == -1) break;
		sorted[i] = results[s];
		fulllookupAddress(results[s].final_eip, (char*)&buf255); 
		if(results[s].steps == limit) 
			printf("%d) offset=0x%-8x   steps=MAX    final_eip=%-8x   %s", i, results[s].offset, results[s].final_eip, buf255 );
		 else 
			printf("%d) offset= 0x%-8x   steps=%-8d   final_eip= %-8x   %s", i, results[s].offset , results[s].steps , results[s].final_eip, buf255 );
		/*real_hexdump(opts.scode + results[s].offset, 10, -1, true);
		nl();
		start_color(mgreen);
		disasm_block(CODE_OFFSET + results[s].offset, 5);
		end_color();*/
		nl();
		results[s].steps = -1; //zero out this entry so it wont be chosen again
	}	

	if(i==1){
		return sorted[0].offset; //there was only one to choose from just run it..
	}

	ret = read_int("\nEnter index:",(char*)&buf);
	if(ret > (i-1) ) return -1; // i = number of results in sorted..
	return sorted[ret].offset;

}

void init_emu(void){
	
	int i =  0;
	void* stack;
	int stacksz;
	
	int regs[] = {0,    0,      0,     0,  0x12fe00,0x12fff0  ,0,    0};
	//            0      1      2      3      4      5         6      7    
	//*regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

	for (i=0;i<8;i++) cpu->reg[(emu_reg32)i] = regs[i];

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
	emu_memory_write_block(mem, CODE_OFFSET, opts.scode,  opts.size);
	
	unsigned char tmp[0x1000]; //extra buffer on end in case they expect it..
	memset(tmp, 0, sizeof(tmp));
	emu_memory_write_block(mem, CODE_OFFSET + opts.size+1,tmp, sizeof(tmp));
	

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
	emu_cpu_eip_set(emu_cpu_get(e), CODE_OFFSET + opts.offset);  //+ opts.offset for getpc mode

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

		if ( cpu->repeat_current_instr == false )
			eipsave = emu_cpu_eip_get(emu_cpu_get(e));

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
					printf("%x\tunhooked call to ordial %s.0x%x\tstep=%d\n", previous_eip , dllFromAddress(cpu->eip), ex->ordial, opts.cur_step );
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


			if ( ret == -1 )  //unhandled error time to bail
			{
				if(opts.verbose < opts.verbosity_onerr)	opts.verbose = opts.verbosity_onerr; 

				start_color(mred);
				printf("%x\t %s", last_good_eip, emu_strerror(e)); 
				end_color();

				cpu->eip = last_good_eip;
				debugCPU(e,true);
				
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
		{"f", "fpath"    ,   "load shellcode from file specified."},
		{"ba", "hexnum"  ,   "break above - breaks if eip > hexnum"},
		{"bp", "hexnum"  ,   "set breakpoint on addr or api name (same as -laa <hexaddr> -vvv)"},
		{"bs", "int"     ,   "break on step (shortcut for -las <int> -vvv)"},
		{"b0", NULL ,        "break if 00 00 add [eax],al"},
		{"cfo", NULL ,       "CreateFileOverRide - if /fopen use handle else open real arg"},
		{"d",  NULL	     ,   "dump unpacked shellcode"},
		{"dir", " folder",   "process all .sc files in <folder> (can be used with -r)"},
		{"disasm", "int" ,   "Disasm int lines (can be used with /foff)"},
		{"dump", NULL,       "view hexdump (can be used with /foff)"},
		{"e", "int"	     ,   "verbosity on error (3 = debug shell)"},
		{"findsc", NULL ,    "detect possible shellcode buffers (brute force)"},
		{"fopen", "file" ,   "Opens a handle to <file> for use with GetFileSize() scanners"},		
		{"foff", "hexnum" ,  "starts execution at file offset"},
		{"h",  NULL		 ,   "show this help"},
		{"hex", NULL,        "show hex dumps for hook reads/writes (paged)"},
		{"hooks", NULL ,     "dumps a list all implemented api hooks"},
		{"i",  NULL		 ,   "enable interactive hooks (file and network)"},
		{"las", "int"	 ,   "log at step ex. -las 100"},
		{"laa", "hexnum" ,   "log at address or api ex. -laa 0x401020 or -laa ReadFile"},
		{"mm", NULL,         "enabled Memory Monitor (logs access to key addresses)"},
		{"mdll", NULL,       "Monitor Dll - log direct access to dll memory (hook detection/patches)"},
		{"nc", NULL,         "no color (if using sending output to other apps)"},
		{"o", "hexnum"   ,   "base offset to use (default: 0x401000)"},
		{"patch", "fpath",   "load patch file <fpath> into libemu memory"},
		{"r", NULL ,         "show analysis report at end of run (includes -mm)"},
		{"redir", "ip:port", "redirect connect to ip (port optional)"},
		{"s", "int"	     ,   "max number of steps to run (def=2000000, -1 unlimited)"},	
		{"t", "int"	     ,   "time to delay (ms) between steps when v=1 or 2"},
		{"u", NULL ,         "unlimited steps (same as -s -1)"},
		{"v",  NULL		 ,   "verbosity, can be used up to 4 times, ex. /v /v /vv"},
		{"- /+", NULL ,      "increments or decrements GetFileSize, can be used multiple times"},
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
	
	int i=0;
	int j=0;
	int tot=0;

	set_hooks(env);

	while ( env->env.win->loaded_dlls[i] != 0 ){
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[i]; 
		printf("\r\n%s\r\n", dll->dllname );
		emu_env_w32_dll_export e = dll->exportx[0];
		while( e.fnname != 0 ){
			if( e.fnhook != 0 ){
				if( IsBadReadPtr(e.fnname ,4) ) break;//for some reason the last null element is optimized out or something?
				if( strlen(e.fnname) == 0)
					printf("\t@%x\r\n", e.ordial);
				else
					printf("\t%s\r\n", e.fnname);
				tot++;
			}
			j++;
			e = dll->exportx[j];
		}
		i++;
		j=0;
	}
	//libemu 2.0 is 5/51
	printf("\r\n  Dlls: %d\r\n Hooks: %d\r\n", i, tot);
	exit(0);
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

	memset(&opts,0,sizeof(struct run_time_options));

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

	for(i=1; i < argc; i++){

		bool handled = false;			
		sl = strlen(argv[i]);

		if( argv[i][0] == '-') argv[i][0] = '/'; //standardize

		buf[0] = argv[i][0];
		buf[1] = argv[i][1];
		buf[2] = '0';
		 		
		if(strstr(buf,"/-") > 0 ){ opts.adjust_getfsize-- ;handled=true;}
		if(strstr(buf,"/+") > 0 ){ opts.adjust_getfsize++ ;handled=true;}
		if(strstr(buf,"/i") > 0 ){opts.interactive_hooks = 1;handled=true;}
		if(strstr(buf,"/v") > 0 ){opts.verbose++; handled=true;}
		if(sl==2 && strstr(buf,"/r") > 0 ){ opts.report = true; opts.mem_monitor = true;handled=true;}
		if(sl==2 && strstr(buf,"/u") > 0 ){opts.steps = -1;handled=true;}
		if(sl==3 && strstr(argv[i],"/nc") > 0 ){   opts.no_color = true; handled=true;}
		if(sl==3 && strstr(argv[i],"/b0") > 0 ){   opts.break0  = true;handled=true;}
		if(sl==4 && strstr(argv[i],"/hex") > 0 ) { opts.show_hexdumps = true;handled=true;}
		if(sl==7 && strstr(argv[i],"/findsc") > 0 ){ opts.getpc_mode = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/vvvv") > 0 ){handled=true; opts.verbose = 4;}
		if(sl==4 && strstr(argv[i],"/vvv") > 0 ) { opts.verbose = 3;handled=true;}
		if(sl==3 && strstr(argv[i],"/vv")  > 0 ) { opts.verbose = 2;handled=true;}
		if(sl==3 && strstr(argv[i],"/mm")  > 0 )  {opts.mem_monitor = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/mdll")  > 0 ){  opts.mem_monitor_dlls  = true;handled=true;}
		if(sl==5 && strstr(argv[i],"/dump")  > 0 ){  opts.hexdump_file = 1;handled=true;}
		if(sl==6 && strstr(argv[i],"/hooks")  > 0 ){ show_supported_hooks();handled=true;}
		if(sl==4 && strstr(argv[i],"/cfo")  > 0 ){ opts.CreateFileOverride = true;handled=true;}
		if(strstr(buf,"/d") > 0 ){ opts.dump_mode = true;handled=true;}
		if(sl==2 && strstr(buf,"/h") > 0 ){ show_help();handled=true;}
		if(sl==2 && strstr(buf,"/?") > 0 ){ show_help();handled=true;}
		if(sl==5 && strstr(argv[i],"/help") > 0 ){ show_help();handled=true;}

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

		if(sl==4 && strstr(argv[i],"/dir") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /dir must specify a folder path as next arg\n");
				exit(0);
			}
			opts.scan_dir = strdup(argv[i+1]);
			i++;handled=true;
		}

		if(strstr(buf,"/o") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /o must specify a hex base addr as next arg\n");
				exit(0);
			}
		    CODE_OFFSET = strtol(argv[i+1], NULL, 16);			
			i++;handled=true;
		}

		if(sl==6 && strstr(argv[i],"/fopen") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /foopen must specify file to open as next arg\n");
				exit(0);
			}
			//opts.fopen = fopen(argv[i+1],"r");  //ms implemented of fread barfs after 0x27000?
			opts.h_fopen = CreateFile(argv[i+1],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
			opts.fopen_fpath = strdup(argv[i+1]);
			opts.fopen_fsize = GetFileSize(opts.h_fopen,0);//file_length(opts.fopen);
			//if((int)opts.fopen < 1){
			if( opts.h_fopen == INVALID_HANDLE_VALUE){
				start_color(myellow);
				printf("FAILED TO OPEN %s", argv[i+1]);
				end_color();
				exit(0);
			}
			printf("fopen(%s) = %x\n", argv[i+1], (int)opts.h_fopen);
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
		    opts.override.connect.host = strdup(argv[i+1]);
			char *port;
			if (( port = strstr(opts.override.connect.host, ":")) != NULL)
			{
				*port = '\0';
				port++;
				opts.override.connect.port = atoi(port);

				if (*opts.override.connect.host == '\0')
				{
					free(opts.override.connect.host);
					opts.override.connect.host = NULL;
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

		if(strstr(buf,"/e") > 0 ){
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

		if(strstr(buf,"/s") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /s must specify num of steps as next arg\n");
				exit(0);
			}
		    opts.steps = atoi(argv[i+1]);	
			i++;handled=true;
		}

		if(strstr(buf,"/t") > 0 ){
			if(i+1 >= argc){
				printf("Invalid option /t must specify delay in millisecs as next arg\n");
				exit(0);
			}
		    opts.time_delay = atoi(argv[i+1]);		
			i++;handled=true;
		}

		if( !handled ){
			start_color(myellow);
			printf("Unknown Option %s\n\n", argv[i]);
			end_color();
			exit(0);
		}

	}


}

void loadsc(void){

	FILE *fp;

	if ( opts.file_mode  ){
	
		fp = fopen(opts.sc_file, "rb");
		if(fp==0){
			start_color(myellow);
			printf("Failed to open file %s\n",opts.sc_file);
			end_color();
			exit(0);
		}
		opts.size = file_length(fp);
		opts.scode = (unsigned char*)malloc(opts.size); 
		fread(opts.scode, 1, opts.size, fp);
		fclose(fp);
		printf("Loaded %x bytes from file %s\n", opts.size, opts.sc_file);
	}
	
	if(opts.size==0){
		printf("No shellcode loaded must use either /f or /S options\n");
		show_help();
		return;
	}

}



int main(int argc, char *argv[])
{
	int i=0;
		
	disable_mm_logging = true;
	memset(&emm, 0, sizeof(emm));
	memset(&mallocs, 0 , sizeof(mallocs));
	
	SetConsoleCtrlHandler(ctrl_c_handler, TRUE); //http://msdn.microsoft.com/en-us/library/ms686016

	hCon = GetStdHandle( STD_INPUT_HANDLE );
	hConOut = GetStdHandle( STD_OUTPUT_HANDLE );

	DWORD old;
	GetConsoleMode(hCon, &old);
	orgt = old;
	old &= ~ENABLE_LINE_INPUT;
	SetConsoleMode(hCon, old);

	signal(SIGABRT,restore_terminal);
    signal(SIGTERM,restore_terminal);
	atexit(atexit_restore_terminal);

	parse_opts(argc, argv);

reinit:
	e = emu_new();
	cpu = emu_cpu_get(e);
	mem = emu_memory_get(e);
	env = emu_env_new(e);
	
	//emu_log_level_set( emu_logging_get(e),  EMU_LOG_DEBUG);

	if ( env == 0 ){ printf("%s\n%s\n", emu_strerror(e), strerror(emu_errno(e))); exit(-1);}

	if(opts.scan_dir != NULL){
		HandleDirMode(opts.scan_dir);
		exit(0);
	}

	loadsc();
	init_emu();	
	
	if(opts.patch_file != NULL) LoadPatch(opts.patch_file);

	if(opts.getpc_mode){
		opts.offset = find_sc();
		if( opts.offset == -1) return -1;
		opts.getpc_mode = false;
		goto reinit; //this gives us a full reinitilization of the whole envirnoment for the run..had a weird bug otherwise..
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
		if(opts.mem_monitor) printf("Memory monitor enabled..\n"); 
		emu_memory_set_access_monitor((uint32_t)mm_hook);
		while(mm_points[i].address != 0){
			emu_memory_add_monitor_point(mm_points[i++].address);
		}
	}

	if(opts.mem_monitor || opts.report || opts.mem_monitor_dlls){
 		if(opts.mem_monitor_dlls) printf("Memory monitor for dlls enabled..\n");
		emu_memory_set_range_access_monitor((uint32_t)mm_range_callback);
		i=0;
		while(mm_ranges[i].start_at != 0){
			emu_memory_add_monitor_range(mm_ranges[i].id, mm_ranges[i].start_at, mm_ranges[i].end_at);
			i++;
		}
	}
	
	if(opts.report){ //monitor writes to main code mem.
		emu_memory_add_monitor_range(0x66, CODE_OFFSET, CODE_OFFSET + opts.size); 
    }
	//---- end memory monitor init 

	printf("Initilization Complete..\n");

	if(opts.adjust_getfsize != 0) printf("Adjusting GetFileSize by %d\n", opts.adjust_getfsize);
	
	if(opts.hexdump_file == 1){
		hexdump_color = true; //highlights possible start addresses (90,E8,E9)
		if(opts.offset >= opts.size ) opts.offset = 0;
		if(opts.offset > 0) printf("Starting at offset %x\n", opts.offset);
		real_hexdump(opts.scode+opts.offset, opts.size-opts.offset,0,false);
		return 0;
	}

	if(opts.disasm_mode > 0){
		if(opts.offset >= opts.size ) opts.offset = 0;
		if(opts.offset > 0) printf("Starting at offset %x\n", opts.offset);
		start_color(mgreen);
		disasm_block(CODE_OFFSET+opts.offset, opts.disasm_mode);
		end_color();
		return 0;
	}

	
	if(opts.offset > 0){
		printf("Execution starts at file offset %x Opcodes: ", opts.offset);
		real_hexdump(opts.scode + opts.offset, 10,-1,true);
		nl();
		start_color(mgreen);
		disasm_block(CODE_OFFSET+opts.offset, 5);
		end_color();
		nl();
	}

	if( opts.override.connect.host != NULL){
		printf("Override connect host active %s\n", opts.override.connect.host);
	}

	if( opts.override.connect.port != 0){
		printf("Override connect port active %d\n", opts.override.connect.port);
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

	if(opts.file_mode == false)	show_help();
	if(opts.dump_mode) printf("Dump mode Active...\n");
		
	if(opts.interactive_hooks){
		start_color(myellow);
		printf("Interactive Hooks enabled\n");
		end_color();
	}

	printf("Max Steps: %d\n", opts.steps);
	printf("Using base offset: 0x%x\n", CODE_OFFSET);
	if(opts.verbose>0) printf("Verbosity: %i\n", opts.verbose);

	nl();
	run_sc();

	return 0;
	 
}

void LoadPatch(char* fpath){
	
	patch p;
	size_t r = sizeof(patch);
	long curpos=0;
	int i = 0;
	char *buf = 0;
	char addr[12];
	uint32_t memAddress=0;

	//patch file format is an array of patch structures at beginning 
	//of file terminated by empty struct at end. field dataOffset points
	//to the raw start file offset of the patch file for the data to load.

	FILE *f = fopen(fpath, "rb");
	if( f == 0 ){
		printf("Failed to open patch file: %s\n", fpath);
		return;
	}

	printf("Loading patch file %s\n", fpath);

	r = fread(&p, 16,1,f);

	while( p.dataOffset > 0 ){
		curpos = ftell(f);

		if( fseek(f, p.dataOffset, SEEK_SET) != 0 ){
			printf("Patch: %d  - Error seeking data offset %x\n", i, p.dataOffset);
			break;
		}

		buf = (char*)malloc(p.dataSize); 
		r = fread(buf, 1, p.dataSize, f);
		if( r != p.dataSize ){
			printf("patch %d - failed to read full size %x readsz=%x\n", i, p.dataSize, r);
			break;
		}

		memset(addr, 0, 12);
		memcpy(addr, p.memAddress, 8); //no trailing null to keep each entry at 16 bytes
		memAddress = strtol(addr, NULL, 16);	

		emu_memory_write_block(mem, memAddress, buf, p.dataSize);
		printf("Applied patch %d va=%x sz=%x\n", i, memAddress, p.dataSize); 
		free(buf);

		fseek(f, curpos, SEEK_SET);
		r = fread(&p, sizeof(patch),1,f); //load next patch
		i++;
	}

	fclose(f);

}

bool FolderExists(char* folder)
{
	DWORD rv = GetFileAttributes(folder);
	if( !(rv & FILE_ATTRIBUTE_DIRECTORY) ) return false;
	return true;
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
	int i=0;

	if(strlen(folder) > 300) return;
	sprintf(cmdline, "%s\\%s", folder, "*.sc");

	hSearch = FindFirstFile(cmdline, &FileData); 
	if (hSearch == INVALID_HANDLE_VALUE){ 
	    printf("No .sc files found in %s\n",folder); 
	    return;
	} 
	
	system("cls");
	printf("\n\n  Processing all sc files in %s\n\n", folder);

	while(1){ 
		printf("  %s\n", FileData.cFileName); 
		sprintf(cmdline, "%s\\%s", folder, FileData.cFileName);
		GetShortPathName(cmdline, (char*)&shortname, 500);
		
		if(opts.report)
			sprintf(cmdline, "scdbg -f %s >> %s\\report.txt", shortname, folder);  //one long report
		else
			sprintf(cmdline, "scdbg -f %s > %s.txt", shortname, shortname);      //individual files

		system(cmdline);
		i++;
		if (!FindNextFile(hSearch, &FileData)) break;
	}

	printf("\n  Found %d files\n\n", i);
	FindClose(hSearch);
}














