Attribute VB_Name = "Module1"

Global e As Long
Global cpu As Long
Global mem As Long
Global env As Long


Public Enum emu_reg32
    eax = 0
    ecx
    edx
    ebx
    esp
    ebp
    esi
    edi
End Enum

Public Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" ( _
                        Destination As Byte, _
                        ByVal Source As Long, _
                        ByVal Length As Long)

'struct emu_env_hook *emu_env_w32_eip_check(struct emu_env *env);
Public Declare Function emu_env_w32_eip_check Lib "vslibemu" (ByVal hEnv As Long) As Long

'uint32_t emu_disasm_addr(struct emu_cpu *c, uint32_t eip, char *str);
Public Declare Function emu_disasm_addr Lib "vslibemu" (ByVal hCpu As Long, ByVal eip As Long, ByRef buf_99 As Byte) As Long

'int32_t emu_cpu_run(struct emu_cpu *c);
Public Declare Function emu_cpu_run Lib "vslibemu" (ByVal hCpu As Long) As Long

'uint32_t emu_cpu_eip_get(struct emu_cpu *c);
Public Declare Function emu_cpu_eip_get Lib "vslibemu" (ByVal hCpu As Long) As Long

'int32_t emu_cpu_parse(struct emu_cpu *c);
Public Declare Function emu_cpu_parse Lib "vslibemu" (ByVal hCpu As Long) As Long

'int32_t emu_cpu_step(struct emu_cpu *c);
Public Declare Function emu_cpu_step Lib "vslibemu" (ByVal hCpu As Long) As Long

'void emu_cpu_eip_set(struct emu_cpu *c, uint32_t eip);
Public Declare Sub emu_cpu_eip_set Lib "vslibemu" (ByVal hCpu As Long, ByVal eip As Long)

'struct emu *emu_new(void);
Public Declare Function emu_new Lib "vslibemu" () As Long

'struct emu_cpu *emu_cpu_get(struct emu *e);
Public Declare Function emu_cpu_get Lib "vslibemu" (ByVal hEmu As Long) As Long

'struct emu_memory *emu_memory_get(struct emu *e);
Public Declare Function emu_memory_get Lib "vslibemu" (ByVal hEmu As Long) As Long

'struct emu_env *emu_env_new(struct emu *e);
Public Declare Function emu_env_new Lib "vslibemu" (ByVal hEmu As Long) As Long

'const char *emu_strerror(struct emu *e);
Public Declare Function emu_strerror Lib "vslibemu" (ByVal hEmu As Long) As Long

'uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu_p, enum emu_reg32 reg);
Public Declare Function emu_cpu_reg32_get Lib "vslibemu" (ByVal hCpu As Long, ByVal reg As emu_reg32) As Long

'void emu_cpu_reg32_set(struct emu_cpu *cpu_p, enum emu_reg32 reg, uint32_t val);
Public Declare Sub emu_cpu_reg32_set Lib "vslibemu" (ByVal hCpu As Long, ByVal reg As emu_reg32, ByVal value As Long)

'int32_t emu_memory_write_block(struct emu_memory *m, uint32_t addr, void *src, size_t len);
Public Declare Function emu_memory_write_block Lib "vslibemu" ( _
            ByVal hMem As Long, _
            ByVal addr As Long, _
            ByRef b As Byte, _
            ByVal Length As Long) As Long
            
'int32_t emu_memory_read_block(struct emu_memory *m, uint32_t addr, void *dest, size_t len);
Public Declare Function emu_memory_read_block Lib "vslibemu" ( _
            ByVal hMem As Long, _
            ByVal addr As Long, _
            ByRef b As Byte, _
            ByVal Length As Long) As Long

'int32_t emu_memory_read_byte(struct emu_memory *m, uint32_t addr, uint8_t *byte);
Public Declare Function emu_memory_read_byte Lib "vslibemu" ( _
            ByVal hMem As Long, _
            ByVal addr As Long, _
            ByRef b As Byte _
            ) As Long


'int32_t emu_env_w32_export_new_hook(struct emu_env *env,
'                                const char *exportname,
'                                int32_t (__stdcall *fnhook)(struct emu_env *env, struct emu_env_hook *hook),
'                                void *userdata);

Public Declare Function emu_env_w32_export_new_hook Lib "vslibemu" _
            (ByVal hEnv As Long, _
              ByVal export As String, _
              ByVal lpfnHook As Long, _
              ByVal userdata As Long) As Long
              
'int32_t __stdcall new_user_hook_LoadLibraryA(struct emu_env *env, struct emu_env_hook *hook)
Public Function LoadLibrary(ByVal env As Long, ByVal hook As Long) As Long
    
    Form1.List1.AddItem "Loadlibrary hook called!"
    emu_cpu_reg32_set cpu, eax, &H7C80000
    
End Function
