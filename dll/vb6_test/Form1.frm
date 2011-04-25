VERSION 5.00
Begin VB.Form Form1 
   Caption         =   "Form1"
   ClientHeight    =   5490
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10110
   LinkTopic       =   "Form1"
   ScaleHeight     =   5490
   ScaleWidth      =   10110
   StartUpPosition =   3  'Windows Default
   Begin VB.ListBox List1 
      BeginProperty Font 
         Name            =   "System"
         Size            =   9.75
         Charset         =   0
         Weight          =   700
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   5100
      Left            =   45
      TabIndex        =   0
      Top             =   90
      Width           =   9960
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
   
    
Function GetError() As String
    Dim b() As Byte
    ReDim b(1000)
    Dim lpError  As Long
    
    lpError = emu_strerror(e)
    
    If lpError <> 0 Then
        CopyMemory b(0), lpError, 999
    End If
    
    GetError = StrConv(b(), vbUnicode, &H409)
    
    lpError = InStr(GetError, Chr(0))
    
    If lpError > 0 Then
        GetError = Mid(GetError, 1, lpError - 1)
    End If
    
    GetError = Replace(GetError, vbLf, Empty)
    
End Function

Function GetDisasm(eip As Long) As String
    Dim r As Long
    Dim b() As Byte
    ReDim b(100)
    r = emu_disasm_addr(cpu, eip, b(0))
    GetDisasm = StrConv(b, vbUnicode, &H409)
End Function

Function isIde() As Boolean
    On Error Resume Next
    Debug.Print 1 / 0
    isIde = IIf(Err.Number = 0, False, True)
End Function

Private Sub Form_Load()
    
    If isIde() Then
        If Dir(App.Path & "\vslibemu.dll") = "" Then
           MsgBox "You need to place a copy of the dll in the project directory to run this in the IDE", vbExclamation
           Exit Sub
        End If
    End If
    
    Dim b() As Byte
    
    e = emu_new()
    cpu = emu_cpu_get(e)
    mem = emu_memory_get(e)
    env = emu_env_new(e)
    
    List1.AddItem "e = " & Hex(e)
    List1.AddItem "cpu = " & Hex(cpu)
    List1.AddItem "mem = " & Hex(mem)
    List1.AddItem "env = " & Hex(env)
    
    If env = 0 Then
        MsgBox "Error starting up win32 envirnoment"
    End If
        'printf("%s\n%s\n", emu_strerror(e), strerror(emu_errno(e))); exit(-1);}
    
    emu_cpu_reg32_set cpu, esp, &H12FE00
    emu_cpu_reg32_set cpu, ebp, &H12FFF0
    
    ReDim b(&H12FFF0 - &H12FE00 + 500)
    r = emu_memory_write_block(mem, &H12FE00 - 250, b(0), UBound(b))
    List1.AddItem "Write of stack memory: " & r & " size: " & UBound(b)
  
    r = emu_env_w32_export_new_hook(env, "LoadLibraryA", AddressOf LoadLibrary, 0)
    List1.AddItem "Set of api hook: " & r
    
    Dim sc As String
'    /*  00436A32     B8 00000000    MOV EAX,0
'        00436A37     40             INC EAX'
'
'        00436A3D     68 6C333200    PUSH 32336C
'        00436A42     68 7368656C    PUSH 6C656873
'        00436A47     54             PUSH ESP
'        00436A48     68 771D807C    PUSH 7C801D77
'        00436A4D     59             POP ECX
'        00436A4E     FFD1           CALL ECX
'
'        686C333200687368656C5468771D807C59FFD1   */

    sc = Chr("&h68") & Chr("&h6C") & Chr("&h33") & Chr("&h32") & Chr("&h00") & _
         Chr("&h68") & Chr("&h73") & Chr("&h68") & Chr("&h65") & Chr("&h6C") & _
         Chr("&h54") & Chr("&h68") & Chr("&h77") & Chr("&h1D") & Chr("&h80") & _
         Chr("&h7C") & Chr("&h59") & Chr("&hFF") & Chr("&hD1") & Chr("&hCC")
    
    'sc = Chr("&hB8") & Chr("&h0") & Chr("&h0") & Chr("&h0") & Chr("&h0") & Chr("&h40") & Chr("&hcc")
    
   
    b() = StrConv(sc, vbFromUnicode, &H409)
    
    Dim eip As Long
    eip = &H401000
    
    'Dim r As Long
    'write shellcode to memory
    r = emu_memory_write_block(mem, eip, b(0), UBound(b))
    List1.AddItem "Memory Write = " & r & " size=" & UBound(b)
    
    Dim bb As Byte
    r = emu_memory_read_byte(mem, eip, bb)
    List1.AddItem "Memory ReadByte = " & r & " bb=" & Hex(bb)
    
    emu_cpu_eip_set cpu, eip
    List1.AddItem "Eip = " & Hex(emu_cpu_eip_get(cpu))
     
    For i = 0 To 6
        
        hook = emu_env_w32_eip_check(env)
        
        If hook = 0 Then
        
            r = emu_cpu_parse(cpu)
            If r = -1 Then
                List1.AddItem "Failed to parse i=" & i
                Exit For
            End If
            
            eip = emu_cpu_eip_get(cpu)
            List1.AddItem Hex(eip) & vbTab & GetDisasm(eip)
            
            r = emu_cpu_step(cpu)
            If r = -1 Then
                List1.AddItem "Failed to step i=" & i
                Exit For
            End If
        End If
        
    Next
    
    List1.AddItem "Error: " & GetError()
    
    'emu_cpu_reg32_set cpu, eax, 1
    List1.AddItem "Steps: " & i & "  Eax is now: " & Hex(emu_cpu_reg32_get(cpu, eax))
    

End Sub
