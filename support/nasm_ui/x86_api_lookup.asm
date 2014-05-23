;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Architecture: x86
; Size: 137 bytes
;-----------------------------------------------------------------------------;

; Input: The hash of the API To Call And all its parameters must be pushed onto stack.
; Output: The return value from the API Call will be In EAX.
; Clobbers: EAX, ECX And EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP And EBP can be expected To remain un-clobbered.
; Note: This Function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This Function Is unable To Call forwarded exports.
;
; This has been slightly modified to return the api address instead of automatically call it -dz

[BITS 32]

api_call:
  pushad                 ; We Preserve all the registers For the caller, bar EAX And ECX.
  mov ebp, esp           ; Create a new stack frame
  Xor edx, edx           ; Zero EDX
  mov edx, [fs:edx+48]   ; Get a pointer To the PEB
  mov edx, [edx+12]      ; Get PEB->Ldr
  mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
next_mod:                ;
  mov esi, [edx+40]      ; Get pointer To modules name (unicode string)
  movzx ecx, word [edx+38] ; Set ECX To the length we want to check 
  Xor edi, edi           ; Clear EDI which will store the hash of the module name
loop_modname:            ;
  Xor eax, eax           ; Clear EAX
  lodsb                  ; Read In the Next byte of the name
  cmp al, 'a'            ; Some versions of Windows use lower case module names
  jl not_lowercase       ;
  Sub al, 0x20           ; If so normalise To uppercase
not_lowercase:           ;
  ror edi, 13            ; Rotate Right our hash value
  add edi, eax           ; Add the Next byte of the name
  Loop loop_modname      ; Loop untill we have read enough
  ; We now have the module hash computed
  push edx               ; Save the current position In the module list For later
  push edi               ; Save the current module hash For later
  ; Proceed To itterate the export address table, 
  mov edx, [edx+16]      ; Get this modules base address
  mov eax, [edx+60]      ; Get PE header
  add eax, edx           ; Add the modules base address
  mov eax, [eax+120]     ; Get export tables RVA
  test eax, eax          ; Test If no export address table Is present
  jz get_next_mod1       ; If no EAT present, process the Next module
  add eax, edx           ; Add the modules base address
  push eax               ; Save the current modules EAT
  mov ecx, [eax+24]      ; Get the number of Function names  
  mov ebx, [eax+32]      ; Get the rva of the Function names
  add ebx, edx           ; Add the modules base address
  ; Computing the module hash + Function hash
get_next_func:           ;
  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the Next module
  dec ecx                ; Decrement the Function name counter
  mov esi, [ebx+ecx*4]   ; Get rva of Next module name
  add esi, edx           ; Add the modules base address
  Xor edi, edi           ; Clear EDI which will store the hash of the Function name
  ; And compare it To the one we want
loop_funcname:           ;
  Xor eax, eax           ; Clear EAX
  lodsb                  ; Read In the Next byte of the ASCII Function name
  ror edi, 13            ; Rotate Right our hash value
  add edi, eax           ; Add the Next byte of the name
  cmp al, ah             ; Compare AL (the Next byte from the name) To AH (null)
  jne loop_funcname      ; If we have Not reached the null terminator, continue
  add edi, [ebp-8]       ; Add the current module hash To the Function hash
  cmp edi, [ebp+36]      ; Compare the hash To the one we are searchnig For 
  jnz get_next_func      ; Go compute the Next Function hash If we have Not found it
  ; If found, fix up stack, Call the Function And Then value Else compute the Next one...
  pop eax                ; Restore the current modules EAT
  mov ebx, [eax+36]      ; Get the ordinal table rva      
  add ebx, edx           ; Add the modules base address
  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
  mov ebx, [eax+28]      ; Get the Function addresses table rva  
  add ebx, edx           ; Add the modules base address
  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
  add eax, edx           ; Add the modules base address To get the functions actual VA
  ; We now fix up the stack And perform the Call To the desired function...
finish:
  mov [esp+36], eax      ; Overwrite the old EAX value With the desired api address For the upcoming popad
  pop ebx                ; Clear off the current modules hash
  pop ebx                ; Clear off the current position In the module list
  popad                  ; Restore all of the callers registers, bar EAX, ECX And EDX which are clobbered
  pop edx                ; this is our return address
  pop ecx                ; remove the hash value given to us
  push edx               ; restore return address
  ret                    ; and ret back.. eax = api address
get_next_mod:            ;
  pop eax                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
  pop edi                ; Pop off the current (now the previous) modules hash
  pop edx                ; Restore our position In the module list
  mov edx, [edx]         ; Get the Next module
  jmp short next_mod     ; Process this module
