VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CLibemu"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False

Property Let reg32(reg As emu_reg32, value As Long)
    emu_cpu_reg32_set cpu, reg, value
End Property

Property Get reg32(reg As emu_reg32) As Long
    reg32 = emu_cpu_reg32_get(cpu, reg)
End Property

Property Let eip(value As Long)
    emu_cpu_eip_set cpu, value
End Property

Property Get eip() As Long
    eip = emu_cpu_eip_get(cpu)
End Property

Function SetHook(export As String, callback As Long) As Boolean
     If emu_env_w32_export_new_hook(env, export, callback, 0) = 0 Then SetHook = True
End Function

Function WriteBlock(addr As Long, buf As String) As Boolean
    Dim b() As Byte
    b() = StrConv(buf, vbFromUnicode, &H409)
    If emu_memory_write_block(mem, addr, b(0), UBound(b) + 1) <> -1 Then WriteBlock = True
End Function

Function WriteByteBuf(addr As Long, b() As Byte) As Boolean
    If emu_memory_write_block(mem, addr, b(0), UBound(b) + 1) <> -1 Then WriteByteBuf = True
End Function

Function Step() As Boolean
    If emu_cpu_parse(cpu) = -1 Then GoTo failed
    If emu_cpu_step(cpu) = -1 Then GoTo failed
    Step = True
    Exit Function
failed:
    Step = False
End Function


Function Initilize() As Boolean
    e = emu_new()
    cpu = emu_cpu_get(e)
    mem = emu_memory_get(e)
    env = emu_env_new(e)
    If e = 0 Or cpu = 0 Or mem = 0 Or env = 0 Then Exit Function
    Initilize = True
End Function

Function ReadAndPopStringArg(Optional maxLen As Long = 256) As String
    ReadAndPopStringArg = ReadString(pop_dword(), maxLen)
End Function

Function pop_dword() As Long
    Dim value As Long
    Dim vesp As Long
    vesp = emu_cpu_reg32_get(cpu, esp)
    emu_memory_read_dword mem, vesp, value
    emu_cpu_reg32_set cpu, esp, vesp + 4
    pop_dword = value
End Function

Function ReadString(addr As Long, Optional maxLen As Long = 256) As String
    Dim tmp As String
    Dim b() As Byte
    ReDim b(maxLen)
    emu_memory_read_block mem, addr, b(0), maxLen
    tmp = StrConv(b(), vbUnicode)
    a = InStr(tmp, Chr(0))
    If a > 0 Then tmp = Mid(tmp, 1, a - 1)
    ReadString = tmp
End Function

Function GetError() As String
    Dim lpError  As Long
    lpError = emu_strerror(e)
    GetError = CStrToVB(lpError)
End Function

'used for reading char* pointers from the dll messages, (not from the emulator memory)
Function CStrToVB(ByVal addr As Long) As String
    Dim b() As Byte
    ReDim b(1000)
    
    If addr = 0 Then Exit Function
    
    CopyMemory b(0), addr, 999
    CStrToVB = StrConv(b(), vbUnicode, &H409)
    
    addr = InStr(CStrToVB, Chr(0))
    
    If addr > 0 Then
        CStrToVB = Mid(CStrToVB, 1, addr - 1)
    End If
    
    CStrToVB = Replace(CStrToVB, vbLf, Empty)
    
End Function

Function GetDisasm(Optional va As Long) As String
    Dim r As Long
    Dim b() As Byte
    ReDim b(100)
    Dim eip As Long
    If va = 0 Then eip = emu_cpu_eip_get(cpu) Else eip = va
    r = emu_disasm_addr(cpu, eip, b(0))
    GetDisasm = StrConv(b, vbUnicode, &H409)
End Function

