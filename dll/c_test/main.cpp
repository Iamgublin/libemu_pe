#include <stdio.h>
#include <windows.h>

#pragma comment( lib, "./../vslibemu.lib" )
#include "libemu.h"


#define POP_DWORD(cpu, dst_p) \
{ int32_t ret = emu_memory_read_dword(cpu->mem, cpu->reg[esp], dst_p); \
if( ret != 0 ) \
	return ret; \
else \
	cpu->reg[esp] += 4; }


struct emu *e = 0;          
struct emu_cpu *cpu = 0;
struct emu_memory *mem = 0;
struct emu_env *env = 0;


int32_t	__stdcall new_user_hook_LoadLibraryA(struct emu_env *env, struct emu_env_hook *hook)
{
/* LoadLibraryA(LPCTSTR lpFileName); */
   struct emu_string *dllstr = emu_string_new();
   uint32_t eip_save;
   uint32_t dllname_ptr;

	POP_DWORD(cpu, &eip_save);
    POP_DWORD(cpu, &dllname_ptr);
    	
    emu_memory_read_string(mem, dllname_ptr, dllstr, 256);
	char *dllname = emu_string_char(dllstr);

	printf("%x\tLoadLibraryA(%s)\t--> HOOK RAN OK\n",eip_save, dllname);

	cpu->reg[eax] = 0x7800000;
	
	emu_string_free(dllstr);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

void __cdecl main(void){
	
	e = emu_new();
	cpu = emu_cpu_get(e);
	mem = emu_memory_get(e);
	env = emu_env_new(e);
	
	//emu_log_level_set( emu_logging_get(e),  EMU_LOG_DEBUG);

	if ( env == 0 ){ printf("%s\n%s\n", emu_strerror(e), strerror(emu_errno(e))); exit(-1);}

	int i =  0;
	void* stack;
	int stacksz;

	//            0      1      2      3      4      5         6      7    
	int regs[] = {0,    0,      0,     0,  0x12fe00,0x12fff0  ,0,    0};
	//*regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};

	for (i=0;i<8;i++) cpu->reg[(emu_reg32)i] = regs[i];

	stacksz = regs[ebp] - regs[esp] + 500;
	stack = malloc(stacksz);
	memset(stack, 0, stacksz);
	
	//printf("writing initial stack space\n");
	emu_memory_write_block(mem, regs[esp] - 250, stack, stacksz);

	emu_env_w32_export_new_hook(env, "LoadLibraryA", new_user_hook_LoadLibraryA, NULL);

	/*	00436A32     B8 00000000    MOV EAX,0
		00436A37     40             INC EAX

		00436A3D     68 6C333200    PUSH 32336C
		00436A42     68 7368656C    PUSH 6C656873
		00436A47     54             PUSH ESP
		00436A48     68 771D807C    PUSH 7C801D77
		00436A4D     59             POP ECX
		00436A4E     FFD1           CALL ECX 

		686C333200687368656C5468771D807C59FFD1   */

	unsigned char shellcode[20] = {
		0x68, 0x6C, 0x33, 0x32, 0x00, 0x68, 0x73, 0x68, 0x65, 0x6C, 0x54, 0x68, 0x77, 0x1D, 0x80, 0x7C, 
		0x59, 0xFF, 0xD1, 0xCC
	};

	//write shellcode to memory
	emu_memory_write_block(mem, 0x401000, shellcode,  20);

	emu_cpu_eip_set(cpu, 0x401000);
	system("cls");

	int step=0;
	char* buf = (char*)malloc(100);

	while(1){
		
		struct emu_env_hook *hook = NULL;
		hook = emu_env_w32_eip_check(env);

		if(hook == NULL){
			if( emu_cpu_parse(cpu) == -1){
				printf("step %d  parse failed error: %s", step, emu_strerror(e));
				break;
			}
			
			emu_disasm_addr(cpu, cpu->eip, buf);
			printf("%x\t%s\n", cpu->eip, buf);
			
			if( emu_cpu_step(cpu) == -1){
				printf("step %d  step failed error: %s", step, emu_strerror(e));
				break;
			}
		}
			
	}

	printf("Run complete eax is: %x\n\n", cpu->reg[eax]);
	

}
