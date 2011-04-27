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

Private Sub Form_Load()
    
    Dim b() As Byte
    Dim eip As Long
    Dim r As Long
    Dim bb As Byte

    If Not emu.Initilize() Then
        MsgBox "Failed to initilize library make sure a copy of the dll is in WinDir or the app home directory", vbExclamation
        Exit Sub
    End If
    
    List1.AddItem "e = " & Hex(e) & " cpu = " & Hex(cpu) & " mem = " & Hex(mem) & " env = " & Hex(env)
    
    emu.reg32(esp) = &H12FE00
    emu.reg32(ebp) = &H12FFF0
        
    ReDim b(&H12FFF0 - &H12FE00 + 500)
    emu.WriteByteBuf &H12FE00 - 250, b()
  
    emu.SetHook "LoadLibraryA", AddressOf LoadLibrary
    
    Dim sc As String
'        00436A3D     68 6C333200    PUSH 32336C
'        00436A42     68 7368656C    PUSH 6C656873
'        00436A47     54             PUSH ESP
'        00436A48     68 771D807C    PUSH 7C801D77 ;LoadLibrary Address
'        00436A4D     59             POP ECX
'        00436A4E     FFD1           CALL ECX

    sc = Chr("&h68") & Chr("&h6C") & Chr("&h33") & Chr("&h32") & Chr("&h00") & _
         Chr("&h68") & Chr("&h73") & Chr("&h68") & Chr("&h65") & Chr("&h6C") & _
         Chr("&h54") & Chr("&h68") & Chr("&h77") & Chr("&h1D") & Chr("&h80") & _
         Chr("&h7C") & Chr("&h59") & Chr("&hFF") & Chr("&hD1") & Chr("&hCC")
            
    eip = &H401000
    emu.WriteBlock eip, sc
    
    r = emu_memory_read_byte(mem, eip, bb)
    List1.AddItem "Memory ReadByte = " & r & " bb=" & Hex(bb)
    
    emu.eip = eip
    List1.AddItem "Eip = " & Hex(emu_cpu_eip_get(cpu))
     
    For i = 0 To 100
        
        hook = emu_env_w32_eip_check(env)
        
        If hook = 0 Then
            eip = emu_cpu_eip_get(cpu)
            List1.AddItem Hex(eip) & vbTab & emu.GetDisasm(eip)
            If Not emu.Step() Then Exit For
        End If
        
    Next
    
    List1.AddItem "Error: " & emu.GetError()
    List1.AddItem "Steps: " & i & "  Eax is now: " & Hex(emu_cpu_reg32_get(cpu, eax))
    

End Sub
