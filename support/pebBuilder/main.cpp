
#include <windows.h>
#include <stdio.h>
#include "main.h"
#include <conio.h>

//inloadorder = process, ntdll, kernel32, ...
//inmemorder  = process, ntdll,kernel32, ...
//ininitorder = ntdll, kernel32, ... (process not linked in this list)

//we have been using 0x00251ea0 as the peb address...

#include <stddef.h> //offsetof

	#define dllCount 16
//	#define dllCount 3

//peb       0x00251ea0
//stack 
//old alloc 0x00060000; alloc size before stack conflict 0x0CFE00 - to small...
//allocs    0x00006000; alloc size before stack conflict 0x129E00 
//or allocs 0x00600000; alloc size before dll conflict 0x76BF0000 - 0x00600000 = 0x765F0000 <--
//start esp 0x0012fe00
//start ebp 0x0012fff0

struct emu_env_w32_known_dll known_dlls[] = //do not reorder the first three entries!
{
	{"process",0x400000,0x3000, }, 
	{"ntdll", 0x7C900000, 0xB2000,}, 
	{"kernel32",0x7C800000,0xf6000, }, 
	{"ws2_32",0x71AB0000,0x17000,},
	{"iphlpapi",0x76D60000,0x19000,},
	{"msvcrt", 0x77C10000, 0x58000,},
	{"shell32",  0x7C9C0000,0x817000,},
	{"shdocvw",  0x7E290000, 0x171000,}, 
	{"advapi32",0x77DD0000,0x9B000,}, 
	{"shlwapi", 0x77F60000, 0x76000,},  
	{"urlmon",0x78130000,0xA0000,	},
	{"user32",  0x7E410000,0x00091000,	}, 
	{"wininet", 0x3D930000,0xD1000,	},
	{"psapi", 0x76BF0000,0xB000,	}, /*ends at 76BFB000*/
	{"imagehlp", 0x76C90000,0x29000,}, 
	{"winhttp", 0x4D4F0000,0x59000,}, 
	{NULL, 0, 0,},
};


uint32_t build_peb(uint32_t embed_at, uint32_t *final_size){

	#define name_len 0x50 //80d byte buffer
	#define peb_sz 0x40
	#define ldr_sz 0x60

	struct _LDR m[dllCount];
	struct _PEB peb;
	char names[dllCount][name_len];  
	const char *dll = ".dll";
	const char *sys = "C:\\Windows\\System32"; //40 chars as unicode
	char* tmp = (char*)malloc(name_len);

	memset(names, 0, sizeof(names));
	memset((void*)&m, 0, sizeof(m));
	memset((void*)&peb, 0, sizeof(peb));

	//printf("sizeof PEB = %x \n" , sizeof(_PEB)); //0x28   reserve 0x40 bytes for peb
	//printf("Size of 1ldr = %x ldrs[13] = %x\n", sizeof(_LDR), sizeof(m));  //0x48   0x3a8
    //so we will give each struct 0x60 bytes which will be 1 full empty line between

	uint32_t struct_sz = peb_sz + (ldr_sz * dllCount); 
	uint32_t string_sz = sizeof(names) + 0x100;
	
	*final_size = struct_sz + string_sz;

    //c:\Windows\System32\   20 character long (40 unicode)
	unsigned char* buf = (unsigned char*)VirtualAlloc( (void*)0x21100000, struct_sz + string_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
	uint32_t va_base = (int)buf;

	uint32_t base = embed_at == 0 ? va_base : embed_at;

	printf("Base address is %x\n", base);

	peb.InLoadOrder.Flink = base + peb_sz + offsetof(struct _LDR, InLoadOrder);
	peb.InLoadOrder.Blink = base + peb_sz + ( (dllCount-1) * ldr_sz) + offsetof(struct _LDR, InLoadOrder);
	//printf("peb.ilo.f = %x  peb.ilo.b = %x last=%x count=%d\n", peb.InLoadOrder.Flink, peb.InLoadOrder.Blink, InLoadList[dllCount-1]);

	peb.InMemOrder.Flink = base + peb_sz + offsetof(struct _LDR, InMemOrder);
	peb.InMemOrder.Blink = base + peb_sz + ( (dllCount-1) * ldr_sz) + offsetof(struct _LDR, InMemOrder);
	//printf("peb.imo.f = %x  peb.imo.b = %x\n", peb.InMemOrder.Flink, peb.InMemOrder.Blink);

	peb.InInitOrder.Flink = base + peb_sz + (1 * ldr_sz) + offsetof(struct _LDR, InInitOrder); //skip process entry..
	peb.InInitOrder.Blink = base + peb_sz + ( (dllCount-1) * ldr_sz) + offsetof(struct _LDR, InInitOrder);
	//printf("peb.iio.f = %x  peb.iio.b = %x\n", peb.InInitOrder.Flink, peb.InInitOrder.Blink);

	//initilize the unicode names array 
	for(int i=0 ; i < dllCount; i++){
		int j,k;
		if(i==0){ sprintf(tmp,"%s\\%s.exe", sys, known_dlls[i].dllname); }
		    else{ sprintf(tmp,"%s\\%s.dll", sys, known_dlls[i].dllname); }
		for(j=0;j<strlen(tmp); j++ ) names[i][j*2] = tmp[j];
	}

	for(int i=0 ; i < dllCount; i++){

		int nameLen = strlen(known_dlls[i].dllname) + strlen(".dll");

		m[i].DllBase = known_dlls[i].baseaddress;

		m[i].FullDllName.Length = 40 + (nameLen*2) ;
		m[i].FullDllName.MaximumLength = m[i].FullDllName.Length + 2;
		m[i].FullDllName.Buffer = base + struct_sz + (name_len * i);

		m[i].BaseDllName.Length = (nameLen*2);
		m[i].BaseDllName.MaximumLength = m[i].BaseDllName.Length + 2;
		m[i].BaseDllName.Buffer = m[i].FullDllName.Buffer + 40; //advance from full path to end of sys dir
		
		if(i == dllCount-1){ //then we point back to peb list head
			m[i].InLoadOrder.Flink =  base + offsetof(struct _PEB, InLoadOrder);
			m[i].InMemOrder.Flink  =  base + offsetof(struct _PEB, InMemOrder);
			m[i].InInitOrder.Flink =  base + offsetof(struct _PEB, InInitOrder);
		}else{
			m[i].InLoadOrder.Flink =  base + peb_sz + ( (i+1) * ldr_sz) + offsetof(struct _LDR, InLoadOrder);
			m[i].InMemOrder.Flink =  base + peb_sz +  ( (i+1) * ldr_sz) + offsetof(struct _LDR, InMemOrder);
			if(i!=0)
				m[i].InInitOrder.Flink =  base + peb_sz + ( (i+1) * ldr_sz) + offsetof(struct _LDR, InInitOrder);
		}
		
		if(i==0){
			m[i].InLoadOrder.Blink = base + offsetof(struct _PEB, InLoadOrder);
			m[i].InMemOrder.Blink = base + offsetof(struct _PEB, InMemOrder);
			//no back link for process entry
		}else{
			m[i].InLoadOrder.Blink = base + peb_sz + ( (i-1) * ldr_sz) + offsetof(struct _LDR, InLoadOrder);
			m[i].InMemOrder.Blink  = base + peb_sz + ( (i-1) * ldr_sz) + offsetof(struct _LDR, InMemOrder);
			if(i==1)
				m[i].InInitOrder.Blink = base + offsetof(struct _PEB, InInitOrder);
			else
				m[i].InInitOrder.Blink = base + peb_sz + ( (i-1) * ldr_sz) + offsetof(struct _LDR, InInitOrder);
		}

	}

	memcpy( (void*)va_base, &peb, sizeof(peb));

	for(int i=0; i < dllCount; i++){
		uint32_t addr = va_base + peb_sz + (ldr_sz*i);
		memcpy( (void*)addr, &m[i], sizeof(_LDR) );
		
		addr = va_base + struct_sz + (name_len * i);
		memcpy( (void*)addr, &names[i], name_len );

		if(strstr(known_dlls[i].dllname, "ntdll") > 0){ //test4 nuance..
			unsigned char nuance[19];
			memset(&nuance[0],0xCC, sizeof(nuance));
			memcpy((void*)(addr + name_len - sizeof(nuance)-1), &nuance[0], sizeof(nuance));
		}

	}

	//printf("Data embedded examine now\n");

	//getch();

	return va_base;
	
}

void test_1(uint32_t peb_base){
	
	int k32_base = 0;
	_asm{
			XOR EAX,EAX
			//MOV EAX,DWORD PTR FS:[0x30]   ;Get a pointer to the PEB
			//MOV EAX,DWORD PTR DS:[EAX+12] ;peb->ldr
			mov eax, peb_base
			MOV EAX,DWORD PTR DS:[EAX+20] ;InMemoryOrder module list
			MOV EAX,DWORD PTR DS:[EAX]    ;next module
			MOV EAX,DWORD PTR DS:[EAX]    ;next module
			MOV EAX,DWORD PTR DS:[EAX+16] ;InMemoryOrder+16 = BaseAddress  
			mov k32_base, eax
	}

	printf("Test 1 InMemoryOrder> Kernel32 base is %x ?= 7C800000\n", k32_base );

 }

void test_2(uint32_t peb_base){
	
	int k32_base = 0;

	_asm{
		        //mov     esi, dword ptr fs:[0x30]
                //mov     esi, [esi+12]
				mov esi, peb_base
                mov     esi, [esi+28]   ;InInitializationOrderModuleList
                mov     ebx, [esi+8]    ;InMemoryOrderModuleList.flink ? (ntdll)
			loc_15:                                
				mov     eax, [esi+8]    ;working copy
				mov     edi, [esi+32]   ;InMemoryOrderModuleList (8) +32 = 40 = *BaseDllName
				mov     esi, [esi]      ;InLoadOrderModuleList.Flink?
				cmp     [edi+24], cl
				jnz     short loc_15
				mov     k32_base, eax
	}


	printf("test 2> ntdll base is %x ?= 7C900000\n", k32_base );

 }

void test_3(uint32_t base){
	
	uint32_t k32_base = 0;

	_asm{
			//XOR EAX,EAX
			//MOV EAX,DWORD PTR FS:[EAX+30]
			//TEST EAX,EAX
			//JS SHORT 00401060                         
			//MOV EAX,DWORD PTR DS:[EAX+C]
			//int 3
			mov eax, base
			MOV ESI,DWORD PTR DS:[EAX+0x1C] ;peb.InInitOrder, esi is first ldr.InInit element
			LODS DWORD PTR DS:[ESI]         ;load 1st ldr.IninitOrder.Flink value into eax, esi += 4
			MOV ECX,DWORD PTR DS:[EAX+8]    ;kernel32 base
			mov k32_base, ecx
	}

	printf("Test 3 InInitOrder> k32 base = %x ?= 7C800000\n", k32_base);

}

void test_4(uint32_t base){

	//this one is unsupported right now...

	uint32_t ntdll=0;
	uint32_t k32=0;
	//EBX 7C900000 ntdll.7C900000
	//EBP 7C800000 kernel32.7C800000
	
	_asm{
		//int 3
		AND ECX,0
		//MOV ESI,DWORD PTR FS:[30]
		//MOV ESI,DWORD PTR DS:[ESI+C]
		mov esi, base
		MOV ESI,DWORD PTR DS:[ESI+0x1C]   ; InInitOrder
		MOV EBX,DWORD PTR DS:[ESI+8]      ; 1st entries module base (ntdll)
		mov ntdll, ebx
    scan_next:
		MOV eax,DWORD PTR DS:[ESI+8]      ; module base (scanning)
		mov k32, eax
		MOV EDI,DWORD PTR DS:[ESI+0x20]   ; base dll name
		MOV ESI,DWORD PTR DS:[ESI]        ; InInitOrder.flink
		CMP BYTE PTR DS:[EDI+0x18],CL     ; start of unicode string + 0x18 is it null? (looking for terminating null after kernel32.dll)
		JNZ SHORT scan_next               ; in real peb ntdll + 0x18 is into some other data, in my peb, it is a null spot so this fails       
                                          ; I could support this..but I am not going to get that fussy for one sample, use the patch or poke if you hit this.

	}

	printf("test 4 > ntdll = %x =? 7C900000 \t k32 = %x =? 7C800000\n", ntdll, k32);




}


void harmony_enum_inmemlist(uint32_t peb_base){

	int names[30];
	memset(names,0xAA,sizeof(names));
	int count=0;

	_asm{
	     xor ecx, ecx
		 lea eax, names
		 //mov edx, fs:[0x30]     ; Get a pointer to the PEB
		 //mov edx, [edx+12]      ; Get PEB->Ldr
		 mov edx, peb_base
		 mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
		 mov ebx, edx           ; first module in list
	next_mod:                
		  mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
		  mov [eax], esi
		  add eax, 4
		  mov edx, [edx]         ; Get the next module ? isnt this the InMemoryOrder.InLoadOrder ?
		  cmp edx, ebx           ;if we back to teh first module then thats all..
		  je  done
		  inc ecx                ;increment our count
		  jmp next_mod     ; Process this module
	done:
		  mov count, ecx
	}

	printf("InMemOrderList Found %d modules\n", count);
	char buf[500];

	for(int i=0;i<count;i++){
		memset(buf,0,500);
		int r = WideCharToMultiByte( CP_UTF8, 0, (LPCWSTR)names[i], -1, (LPSTR)&buf[0], 500,  NULL, NULL); 
		printf("\t%d %s\n",i,buf);
	}

}

void harmony_lookup(uint32_t base){

	uint32_t api_address = 0;

	//this will crash if it doesnt find the right hash and makes it all the way back to the peb list head

	_asm{
		  //int 3
		  mov edx, base
  	      push 0xE449F330        ; GetTempPathA
		  call api_lookup
		  mov api_address, eax
		  jmp show_results

	api_lookup:
		  pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
		  mov ebp, esp           ; Create a new stack frame
		  //xor edx, edx           ; Zero EDX
		  //mov edx, [fs:edx+48]   ; Get a pointer to the PEB
		  //mov edx, [edx+12]      ; Get PEB->Ldr
		  mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
	next_mod:                
		  mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
		  movzx ecx, [edx+38]    ; Set ECX to the length we want to check 
		  and ecx, 0xFFFF        ; vc doesnt have the word specifier we only want lower 16 bits?
		  xor edi, edi           ; Clear EDI which will store the hash of the module name
	loop_modname:            
		  xor eax, eax           ; Clear EAX
		  lodsb                  ; Read in the next byte of the name
		  cmp al, 'a'            ; Some versions of Windows use lower case module names
		  jl not_lowercase       ;
		  sub al, 0x20           ; If so normalise to uppercase
	not_lowercase:           
		  ror edi, 13            ; Rotate right our hash value
		  add edi, eax           ; Add the next byte of the name
		  loop loop_modname      ; Loop untill we have read enough
		  ; We now have the module hash computed
		  push edx               ; Save the current position in the module list for later --> bp here to check hash harmony ntdll module hash = 3E9A174F , kernel32 length 1a module hash = 92AF16DA
		  push edi               ; Save the current module hash for later
		  ; Proceed to itterate the export address table, 
		  mov edx, [edx+16]      ; Get this modules base address
		  mov eax, [edx+60]      ; Get PE header
		  add eax, edx           ; Add the modules base address
		  mov eax, [eax+120]     ; Get export tables RVA
		  test eax, eax          ; Test if no export address table is present
		  jz get_next_mod1       ; If no EAT present, process the next module
		  add eax, edx           ; Add the modules base address
		  push eax               ; Save the current modules EAT
		  mov ecx, [eax+24]      ; Get the number of function names  
		  mov ebx, [eax+32]      ; Get the rva of the function names
		  add ebx, edx           ; Add the modules base address
		  ; Computing the module hash + function hash
	get_next_func:           ;
		  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
		  dec ecx                ; Decrement the function name counter
		  mov esi, [ebx+ecx*4]   ; Get rva of next module name
		  add esi, edx           ; Add the modules base address
		  xor edi, edi           ; Clear EDI which will store the hash of the function name --> ESI holds *export name 
		  ; And compare it to the one we want
	loop_funcname:           ;
		  xor eax, eax           ; Clear EAX
		  lodsb                  ; Read in the next byte of the ASCII function name
		  ror edi, 13            ; Rotate right our hash value
		  add edi, eax           ; Add the next byte of the name
		  cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
		  jne loop_funcname      ; If we have not reached the null terminator, continue
		  add edi, [ebp-8]       ; Add the current module hash to the function hash
		  cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for   --> complete hash for module+export
		  //cmp edi, [ebp+0x32]      ; Compare the hash to the one we are searchnig for   --> complete hash for module+export (modified -4 because we didnt call into this lookup fx in this demo)
		  jnz get_next_func      ; Go compute the next function hash if we have not found it
		  ; If found, fix up stack, call the function and then value else compute the next one...
		  pop eax                ; Restore the current modules EAT
		  mov ebx, [eax+36]      ; Get the ordinal table rva      
		  add ebx, edx           ; Add the modules base address
		  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
		  mov ebx, [eax+28]      ; Get the function addresses table rva  
		  add ebx, edx           ; Add the modules base address
		  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
		  add eax, edx           ; Add the modules base address to get the functions actual VA
		  ; We now fix up the stack and perform the call to the desired function...
	finish:
		  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
		  pop ebx                ; Clear off the current modules hash
		  pop ebx                ; Clear off the current position in the module list
		  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
		  pop ecx                ; Pop off the origional return address our caller will have pushed
		  pop edx                ; Pop off the hash value our caller will have pushed
		  push ecx               ; Push back the correct return value
		  //jmp eax                ; Jump into the required function
		  ret
		  //; We now automagically return to the correct caller...
	get_next_mod:            ;
		  pop eax                ; Pop off the current (now the previous) modules EAT
	get_next_mod1:           ;
		  pop edi                ; Pop off the current (now the previous) modules hash
		  pop edx                ; Restore our position in the module list
		  mov edx, [edx]         ; Get the next module
		  jmp short next_mod     ; Process this module
    show_results:
	}

	printf("GetTempPathA %x =? %x\n", api_address, GetProcAddress(GetModuleHandle(L"kernel32"), "GetTempPathA") );

}

void main(int argc, char* argv[]){
	
	uint32_t embed_at = 0;
	uint32_t peb_size = 0;
	uint32_t base = 0;

	printf("pebbuilder.exe usage: no arguments = test mode\n");
	printf("\t\t 1 arg = hex string specifying base address to build PEB for (use 0x00251ea0)\n");
	printf("\t\tOutput file peb.bin\n\n");

	if(argc > 1){
		embed_at = strtoul(argv[1],NULL, 16);
		if(embed_at == 0){
			printf("Error converting %s to hex\n", argv[1]);
			exit(0);
		}
		printf("Building PEB to embed at offset %x (scdbg expects 0x00251ea0)\n",  embed_at);
		base = build_peb(embed_at, &peb_size);
		
		FILE* f = fopen("peb.bin","wb");
		fwrite( (void*)base, 1, peb_size, f);
		fclose(f);

		printf("Written to peb.bin");
		exit(0);
	}

	base = build_peb(embed_at, &peb_size);

	test_1(base);
	test_2(base);
	test_3(base);
	test_4(base); 
	harmony_enum_inmemlist(base);
	
	if( (uint32_t)GetModuleHandle(L"kernel32") == 0x7C800000){
		//the embedded base address of k32 in my test PEB must line up to
		//its address on your system for an export lookup to work...
		harmony_lookup(base);
	}


	getch();





}
