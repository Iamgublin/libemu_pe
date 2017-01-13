VERSION 5.00
Begin VB.Form frmConvert 
   Caption         =   "Convert to binary from hex, %x or %u formats"
   ClientHeight    =   1935
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   7305
   LinkTopic       =   "Form1"
   ScaleHeight     =   1935
   ScaleWidth      =   7305
   StartUpPosition =   2  'CenterScreen
   Begin VB.TextBox txtPad 
      Height          =   345
      Left            =   3780
      TabIndex        =   11
      Top             =   870
      Width           =   945
   End
   Begin VB.CheckBox chkPadding 
      Caption         =   "pad 0x"
      Height          =   315
      Left            =   2970
      TabIndex        =   10
      Top             =   900
      Width           =   825
   End
   Begin VB.TextBox txtXor 
      Height          =   345
      Left            =   1950
      TabIndex        =   9
      Top             =   870
      Width           =   915
   End
   Begin VB.CheckBox chkXor 
      Caption         =   "xor 0x"
      Height          =   285
      Left            =   1110
      TabIndex        =   8
      ToolTipText     =   "supports 1-4 byte xor keys"
      Top             =   930
      Width           =   765
   End
   Begin VB.CheckBox Check3 
      Caption         =   "reload"
      Height          =   315
      Left            =   4740
      TabIndex        =   7
      Top             =   1530
      Width           =   855
   End
   Begin VB.CheckBox Check2 
      Caption         =   "Endian Swap"
      Height          =   315
      Left            =   5910
      TabIndex        =   6
      Top             =   900
      Width           =   1275
   End
   Begin VB.CheckBox Check1 
      Caption         =   "Byte swap"
      Height          =   315
      Left            =   4800
      TabIndex        =   5
      Top             =   900
      Width           =   1035
   End
   Begin VB.TextBox Text2 
      Height          =   285
      Left            =   1050
      TabIndex        =   4
      Top             =   150
      Width           =   6135
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Convert"
      Height          =   375
      Left            =   5730
      TabIndex        =   2
      Top             =   1500
      Width           =   1455
   End
   Begin VB.TextBox Text1 
      Height          =   285
      Left            =   1050
      TabIndex        =   1
      Top             =   510
      Width           =   6135
   End
   Begin VB.Label Label2 
      Caption         =   "input file"
      Height          =   255
      Left            =   150
      TabIndex        =   3
      Top             =   150
      Width           =   855
   End
   Begin VB.Label Label1 
      Caption         =   "Output file"
      Height          =   255
      Left            =   120
      TabIndex        =   0
      Top             =   510
      Width           =   855
   End
End
Attribute VB_Name = "frmConvert"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim p As frmscdbg

Private Sub Command1_Click()

    If Not fso.FileExists(Text2) Then
        MsgBox "Sample file not found?" & vbCrLf & p.scfile, vbCritical
        Exit Sub
    End If
    
    If Not fso.FileExists(p.sctest) Then
        MsgBox "Can not find sctest in app.path exiting", vbCritical
        Exit Sub
    End If
   
    Dim cmdline As String
    Dim outFile As String
    
    outFile = Trim(Text1)
    scfile = GetShortName(Trim(Replace(Text2, Chr(0), Empty)))
    cmdline = GetShortName(p.sctest)
    libemu = GetShortName(fso.GetParentFolder(p.sctest))
    
    If Check1.Value = 1 Then cmdline = cmdline & " -bswap "
    If Check2.Value = 1 Then cmdline = cmdline & " -eswap "
    If chkXor.Value = 1 And isHexNum(txtXor) Then cmdline = cmdline & " -xor 0x" & txtXor
    If chkPadding = 1 And isHexNum(txtPad) Then cmdline = cmdline & " -pad 0x" & txtPad
        
    cmdline = cmdline & " -f " & scfile
    cmdline = cmdline & " -conv """ & outFile & """"
    
    cmdline = "cmd /k chdir /d " & libemu & "\ && " & cmdline
    lastcmdline = cmdline
    
    'todo change to hidden shell and wait and capture output for textbox..
    pid = Shell(cmdline, vbNormalFocus)
    
    If Check3.Value = 1 Then
        For i = 0 To 300
            Sleep 10
            If fso.FileExists(outFile) Then Exit For
        Next
        Sleep 100
        If fso.FileExists(outFile) Then
            p.txtLoadedFile = outFile
            p.loadedFile = outFile
            p.InitInterface fso.ReadFile(outFile)
        End If
    End If
    
    
End Sub

Private Sub Form_Load()
    Set p = frmscdbg
End Sub
