VERSION 5.00
Begin VB.Form frmScTest 
   Caption         =   "scDbg - libemu Shellcode Logger Launch Interface"
   ClientHeight    =   7695
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10140
   LinkTopic       =   "Form3"
   ScaleHeight     =   7695
   ScaleWidth      =   10140
   StartUpPosition =   2  'CenterScreen
   Begin VB.TextBox txtScdbg 
      Height          =   285
      Left            =   720
      OLEDropMode     =   1  'Manual
      TabIndex        =   20
      Top             =   480
      Width           =   9255
   End
   Begin VB.TextBox txtFile 
      Height          =   285
      Left            =   720
      TabIndex        =   18
      Top             =   120
      Width           =   9255
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   5160
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   3
      Top             =   2400
      Width           =   9960
   End
   Begin VB.Frame Frame1 
      Caption         =   "Options"
      Height          =   1455
      Left            =   120
      TabIndex        =   0
      Top             =   840
      Width           =   10005
      Begin VB.TextBox txtManualArgs 
         Height          =   285
         Left            =   1800
         TabIndex        =   16
         Top             =   1080
         Width           =   5955
      End
      Begin VB.TextBox txtStartOffset 
         Height          =   285
         Left            =   8055
         TabIndex        =   13
         Text            =   "0"
         Top             =   180
         Width           =   675
      End
      Begin VB.CheckBox chkOffset 
         Caption         =   "Start Offset  0x"
         Height          =   255
         Left            =   6660
         TabIndex        =   14
         Top             =   195
         Width           =   1515
      End
      Begin VB.TextBox txtFopen 
         Height          =   285
         Left            =   1035
         OLEDropMode     =   1  'Manual
         TabIndex        =   12
         Top             =   675
         Width           =   6720
      End
      Begin VB.CheckBox chkfopen 
         Caption         =   "fopen"
         Height          =   240
         Left            =   225
         TabIndex        =   11
         Top             =   720
         Width           =   1230
      End
      Begin VB.CheckBox ChkMemMon 
         Caption         =   "Monitor DLL Read/Write"
         Height          =   195
         Left            =   5640
         TabIndex        =   10
         Top             =   480
         Width           =   2295
      End
      Begin VB.CheckBox chkFindSc 
         Caption         =   "FindSc"
         Height          =   255
         Left            =   5640
         TabIndex        =   9
         Top             =   180
         Width           =   1095
      End
      Begin VB.CheckBox chkDebugShell 
         Caption         =   "Debug Shell"
         Height          =   195
         Left            =   4080
         TabIndex        =   8
         Top             =   480
         Width           =   1455
      End
      Begin VB.CheckBox chkUnlimitedSteps 
         Caption         =   "Unlimited steps"
         Height          =   255
         Left            =   4080
         TabIndex        =   7
         Top             =   180
         Width           =   1635
      End
      Begin VB.CheckBox chkAdjustOffsets 
         Caption         =   "Show File based offsets"
         Enabled         =   0   'False
         Height          =   195
         Left            =   1920
         TabIndex        =   6
         Top             =   180
         Width           =   1995
      End
      Begin VB.CheckBox chkInteractiveHooks 
         Caption         =   "Use Interactive Hooks"
         Height          =   255
         Left            =   1920
         TabIndex        =   5
         Top             =   420
         Width           =   1935
      End
      Begin VB.CheckBox chkCreateDump 
         Caption         =   "Create Dump"
         Height          =   255
         Left            =   240
         TabIndex        =   4
         Top             =   420
         Width           =   1455
      End
      Begin VB.CommandButton Command1 
         Caption         =   "Launch"
         Height          =   375
         Left            =   8370
         TabIndex        =   2
         Top             =   1035
         Width           =   1575
      End
      Begin VB.CheckBox chkReport 
         Caption         =   "Report Mode"
         Height          =   255
         Left            =   240
         TabIndex        =   1
         Top             =   180
         Width           =   1695
      End
      Begin VB.Label Label1 
         Caption         =   "Manual  Arguments"
         Height          =   285
         Left            =   225
         TabIndex        =   15
         Top             =   1080
         Width           =   1410
      End
   End
   Begin VB.Label Label2 
      Caption         =   "Scdbg"
      Height          =   255
      Index           =   1
      Left            =   120
      TabIndex        =   19
      Top             =   480
      Width           =   855
   End
   Begin VB.Label Label2 
      Caption         =   "File: "
      Height          =   255
      Index           =   0
      Left            =   120
      TabIndex        =   17
      Top             =   120
      Width           =   855
   End
End
Attribute VB_Name = "frmScTest"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim b() As Byte
Dim fso As New CFileSystem2
Dim scfile As String
Dim sctest As String
Dim lastcmdline As String

Private Declare Function GetShortPathName Lib "kernel32" Alias "GetShortPathNameA" (ByVal lpszLongPath As String, ByVal lpszShortPath As String, ByVal cchBuffer As Long) As Long

'file msut exist for this to work which is stupid...
Public Function GetShortName(sFile As String) As String
    Dim sShortFile As String * 67
    Dim lResult As Long

    'Make a call to the GetShortPathName API
    lResult = GetShortPathName(sFile, sShortFile, _
    Len(sShortFile))

    'Trim out unused characters from the string.
    GetShortName = Left$(sShortFile, lResult)

End Function

Public Function InitInterface(fpath As String)
       
    scfile = fpath
    txtFile = scfile
    
    If fso.FileExists(fpath) Then
        Text1 = Form1.Hexdump(fso.ReadFile(fpath))
        b() = StrConv(fso.ReadFile(fpath), vbFromUnicode, LANG_US)
    End If
    
    Me.Visible = True
    
    
End Function

Private Sub Command1_Click()
    
    On Error Resume Next
    
    If Not fso.FileExists(txtScdbg) Then
        MsgBox "Drag and drop scdbg.exe into its textbox. path will be saved."
        Exit Sub
    End If
    
    scfile = fso.GetParentFolder(txtScdbg) & "\sample.sc"
    
    If fso.FileExists(scfile) Then Kill scfile
    fso.WriteFile scfile, StrConv(b(), vbUnicode, LANG_US)

    sctest = txtScdbg
    
    Dim cmdline As String
    
    scfile = Trim(Replace(scfile, Chr(0), Empty))
    cmdline = GetShortName(sctest)
    libemu = GetShortName(fso.GetParentFolder(txtScdbg))
    
    If chkAdjustOffsets.value = 1 Then cmdline = cmdline & " -a"
    If chkInteractiveHooks.value = 1 Then cmdline = cmdline & " -i"
    If chkCreateDump.value = 1 Then cmdline = cmdline & " -d"
    If chkReport.value = 1 Then cmdline = cmdline & " -r"
    If chkUnlimitedSteps.value = 1 Then cmdline = cmdline & " -s -1"
    If chkDebugShell.value = 1 Then cmdline = cmdline & " -vvv"
    If chkFindSc.value = 1 Then cmdline = cmdline & " -findsc"
    If ChkMemMon.value = 1 Then cmdline = cmdline & " -mdll"
    
    If chkOffset.value = 1 Then
        If Not isHexNum(txtStartOffset) Then
            MsgBox "Start offset is not a valid hex number: " & txtStartOffset, vbInformation
            Exit Sub
        End If
        cmdline = cmdline & " -foff " & txtStartOffset
    End If
    
    If chkfopen.value = 1 Then
        If Not fso.FileExists(txtFopen.Text) Then
            MsgBox "You must specify a valid file to open", vbInformation
            Exit Sub
        End If
        cmdline = cmdline & " -fopen " & GetShortName(txtFopen)
    End If
                                
    cmdline = cmdline & " -f sample.sc" & " " & txtManualArgs
    
    cmdline = "cmd /k chdir /d " & libemu & "\ && " & cmdline
    lastcmdline = cmdline
    
    pid = Shell(cmdline, vbNormalFocus)
    
End Sub

Private Sub Form_Load()
    txtScdbg = GetSetting("bulk", "settings", "scdbg", "")
End Sub

Private Sub Form_Unload(Cancel As Integer)
    SaveSetting "bulk", "settings", "scdbg", txtScdbg
End Sub

Private Sub txtScdbg_OLEDragOver(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single, State As Integer)
    On Error Resume Next
    txtScdbg = Data.files(1)
End Sub

Public Function isHexNum(v) As Boolean
    On Error Resume Next
    X = CLng("&h" & v)
    If Err.Number = 0 Then isHexNum = True
    Err.Clear
End Function
