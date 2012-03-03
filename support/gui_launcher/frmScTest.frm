VERSION 5.00
Begin VB.Form frmScTest 
   Caption         =   "scDbg - libemu Shellcode Logger Launch Interface"
   ClientHeight    =   7485
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10140
   LinkTopic       =   "Form3"
   ScaleHeight     =   7485
   ScaleWidth      =   10140
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdLoadFile 
      Caption         =   "..."
      Height          =   315
      Left            =   9240
      TabIndex        =   26
      Top             =   60
      Width           =   795
   End
   Begin VB.TextBox txtLoadedFile 
      Height          =   315
      Left            =   1260
      Locked          =   -1  'True
      OLEDropMode     =   1  'Manual
      TabIndex        =   25
      Text            =   "Can drag and drop here"
      Top             =   60
      Width           =   7815
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
      Height          =   4860
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   3
      Top             =   2580
      Width           =   9960
   End
   Begin VB.Frame Frame1 
      Caption         =   " Options "
      Height          =   2055
      Left            =   60
      TabIndex        =   0
      Top             =   480
      Width           =   10005
      Begin VB.CheckBox chkTemp 
         Caption         =   "temp = file path"
         Height          =   195
         Left            =   240
         TabIndex        =   27
         Top             =   720
         Width           =   1395
      End
      Begin VB.TextBox txtManualArgs 
         Height          =   285
         Left            =   1800
         TabIndex        =   23
         Top             =   1380
         Width           =   5955
      End
      Begin VB.TextBox txtStartOffset 
         Height          =   285
         Left            =   8160
         TabIndex        =   20
         Text            =   "0"
         Top             =   180
         Width           =   675
      End
      Begin VB.CheckBox chkOffset 
         Caption         =   "Start Offset  0x"
         Height          =   255
         Left            =   6780
         TabIndex        =   21
         Top             =   180
         Width           =   1515
      End
      Begin VB.CommandButton cmdrowse 
         Caption         =   "..."
         Height          =   285
         Left            =   7830
         TabIndex        =   19
         Top             =   1020
         Width           =   465
      End
      Begin VB.TextBox txtFopen 
         Height          =   285
         Left            =   1035
         OLEDropMode     =   1  'Manual
         TabIndex        =   18
         Top             =   1020
         Width           =   6720
      End
      Begin VB.CheckBox chkfopen 
         Caption         =   "fopen"
         Height          =   240
         Left            =   240
         TabIndex        =   17
         Top             =   1020
         Width           =   1230
      End
      Begin VB.CheckBox ChkMemMon 
         Caption         =   "Monitor DLL Read/Write"
         Height          =   195
         Left            =   1920
         TabIndex        =   16
         Top             =   720
         Width           =   2295
      End
      Begin VB.CheckBox chkFindSc 
         Caption         =   "FindSc"
         Height          =   255
         Left            =   5640
         TabIndex        =   15
         Top             =   180
         Width           =   1095
      End
      Begin VB.CheckBox chkDebugShell 
         Caption         =   "Debug Shell"
         Height          =   195
         Left            =   4080
         TabIndex        =   14
         Top             =   480
         Width           =   1455
      End
      Begin VB.CheckBox chkUnlimitedSteps 
         Caption         =   "Unlimited steps"
         Height          =   255
         Left            =   4080
         TabIndex        =   13
         Top             =   180
         Width           =   1635
      End
      Begin VB.CheckBox chkApiTable 
         Caption         =   "Scan for Api table"
         Height          =   195
         Left            =   1920
         TabIndex        =   8
         Top             =   180
         Width           =   1995
      End
      Begin VB.CheckBox chkInteractiveHooks 
         Caption         =   "Use Interactive Hooks"
         Height          =   255
         Left            =   1920
         TabIndex        =   7
         Top             =   420
         Width           =   1935
      End
      Begin VB.CheckBox chkCreateDump 
         Caption         =   "Create Dump"
         Height          =   255
         Left            =   240
         TabIndex        =   6
         Top             =   420
         Width           =   1455
      End
      Begin VB.CommandButton Command1 
         Caption         =   "Launch"
         Height          =   375
         Left            =   8370
         TabIndex        =   2
         Top             =   1320
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
         TabIndex        =   22
         Top             =   1380
         Width           =   1410
      End
      Begin VB.Label Label6 
         Caption         =   "scdbg homepage"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   255
         Index           =   8
         Left            =   2460
         TabIndex        =   12
         Top             =   1740
         Width           =   1335
      End
      Begin VB.Label Label6 
         Caption         =   "cmdline"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   255
         Index           =   7
         Left            =   4200
         TabIndex        =   11
         Top             =   1740
         Width           =   675
      End
      Begin VB.Label Label6 
         Caption         =   "Video Demo"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   255
         Index           =   2
         Left            =   5280
         TabIndex        =   10
         Top             =   1740
         Width           =   1035
      End
      Begin VB.Label Label6 
         Caption         =   "Help"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   195
         Index           =   6
         Left            =   6720
         TabIndex        =   9
         Top             =   1740
         Width           =   375
      End
      Begin VB.Label Label6 
         Caption         =   "Libemu HomePage"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   255
         Index           =   4
         Left            =   540
         TabIndex        =   5
         Top             =   1740
         Width           =   1455
      End
      Begin VB.Label Label6 
         Caption         =   "Example"
         BeginProperty Font 
            Name            =   "MS Sans Serif"
            Size            =   8.25
            Charset         =   0
            Weight          =   400
            Underline       =   -1  'True
            Italic          =   0   'False
            Strikethrough   =   0   'False
         EndProperty
         ForeColor       =   &H00FF0000&
         Height          =   255
         Index           =   5
         Left            =   7560
         TabIndex        =   4
         Top             =   1740
         Width           =   735
      End
   End
   Begin VB.Label Label2 
      Caption         =   "Shellcode file"
      Height          =   255
      Left            =   120
      TabIndex        =   24
      Top             =   120
      Width           =   1035
   End
End
Attribute VB_Name = "frmScTest"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim b() As Byte
Dim dlg As New clsCmnDlg
Dim scfile As String
Dim sctest As String
Dim lastcmdline As String
Dim loadedFile As String


'Private Declare Function WinExec Lib "kernel32" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long
'Private Declare Function OpenProcess Lib "kernel32" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As Long
'Private Declare Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
'Private Declare Function CloseHandle Lib "kernel32" (ByVal hObject As Long) As Long
'Private Const SYNCHRONIZE = &H100000
'Private Const INFINITE = &HFFFF

Const INFINITE = &HFFFF
Const STARTF_USESHOWWINDOW = &H1
Private Enum enSW
    SW_HIDE = 0
    SW_NORMAL = 1
    SW_MAXIMIZE = 3
    SW_MINIMIZE = 6
End Enum

Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Byte
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

Private Type SECURITY_ATTRIBUTES
    nLength As Long
    lpSecurityDescriptor As Long
    bInheritHandle As Long
End Type

Private Enum enPriority_Class
    NORMAL_PRIORITY_CLASS = &H20
    IDLE_PRIORITY_CLASS = &H40
    HIGH_PRIORITY_CLASS = &H80
End Enum

Private Declare Function CreateProcess Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As SECURITY_ATTRIBUTES, lpThreadAttributes As SECURITY_ATTRIBUTES, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
Private Declare Function WaitForSingleObject Lib "kernel32" (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
Private Declare Function GetShortPathName Lib "kernel32" Alias "GetShortPathNameA" (ByVal lpszLongPath As String, ByVal lpszShortPath As String, ByVal cchBuffer As Long) As Long


Private Function SuperShell(ByVal App As String, ByVal WorkDir As String, Optional wait As Boolean = False, Optional dwMilliseconds As Long = 0, Optional start_size As enSW = SW_NORMAL, Optional Priority_Class As enPriority_Class = NORMAL_PRIORITY_CLASS) As Boolean

        Dim pclass As Long
        Dim sinfo As STARTUPINFO
        Dim pinfo As PROCESS_INFORMATION
        Dim sec1 As SECURITY_ATTRIBUTES
        Dim sec2 As SECURITY_ATTRIBUTES
        sec1.nLength = Len(sec1)
        sec2.nLength = Len(sec2)
        sinfo.cb = Len(sinfo)
        sinfo.dwFlags = STARTF_USESHOWWINDOW
        sinfo.wShowWindow = start_size
        pclass = Priority_Class
        
        If CreateProcess(vbNullString, App, sec1, sec2, False, pclass, 0&, WorkDir, sinfo, pinfo) Then
            If wait Then WaitForSingleObject pinfo.hProcess, dwMilliseconds
            SuperShell = True
        Else
            SuperShell = False
        End If
        
End Function


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

Public Function InitInterface(Optional Shellcode As String = Empty)
       
    scfile = Empty
    
    If Not checkFor_sctest() Then Command1.Enabled = False
    
    If Len(Shellcode) = 0 Then
        Text1 = "No text selected! you can use demo link."
    Else
        Text1 = HexDump(Shellcode)
        b() = StrConv(Shellcode, vbFromUnicode, LANG_US)
    End If
    
    'Me.Visible = True
    
    
End Function

Function checkFor_sctest() As Boolean
        
        sctest = App.path & "\scdbg.exe"
        If Not fso.FileExists(sctest) Then
            sctest = App.path & "\..\..\scdbg.exe"
            If Not fso.FileExists(sctest) Then
                MsgBox "Can not find scdbg?"
                Exit Function
            End If
        End If
        
        checkFor_sctest = True
        
End Function


Private Sub Check1_Click()

End Sub

Private Sub cmdLoadFile_Click()
    f = dlg.OpenDialog(AllFiles, , "Manually load shellcode file", Me.hwnd)
    If Len(f) = 0 Then Exit Sub
    InitInterface fso.ReadFile(f)
    loadedFile = f
    txtLoadedFile = f
End Sub

Private Sub cmdrowse_Click()
    txtFopen.Text = dlg.OpenDialog(AllFiles)
    chkfopen.Value = 1
End Sub

Private Sub Command1_Click()
    
    On Error Resume Next
    
    scfile = loadedFile
    
    If Not fso.FileExists(scfile) Then
        MsgBox "Sample file not found?" & vbCrLf & scfile, vbCritical
        Exit Sub
    End If
    
    If Not fso.FileExists(sctest) Then
        MsgBox "Can not find sctest in app.path exiting", vbCritical
        Exit Sub
    End If
   
    Dim cmdline As String
    
    scfile = GetShortName(Trim(Replace(scfile, Chr(0), Empty)))
    cmdline = GetShortName(sctest)
    libemu = GetShortName(fso.GetParentFolder(sctest))
    
    If chkApiTable.Value = 1 Then cmdline = cmdline & " -api"
    If chkInteractiveHooks.Value = 1 Then cmdline = cmdline & " -i"
    If chkCreateDump.Value = 1 Then cmdline = cmdline & " -d"
    If chkReport.Value = 1 Then cmdline = cmdline & " -r"
    If chkUnlimitedSteps.Value = 1 Then cmdline = cmdline & " -s -1"
    If chkDebugShell.Value = 1 Then cmdline = cmdline & " -vvv"
    If chkFindSc.Value = 1 Then cmdline = cmdline & " -findsc"
    If ChkMemMon.Value = 1 Then cmdline = cmdline & " -mdll"
    If chkTemp.Value = 1 Then cmdline = cmdline & " -temp " & GetShortName(fso.GetParentFolder(loadedFile))
    
    If chkOffset.Value = 1 Then
        If Not isHexNum(txtStartOffset) Then
            MsgBox "Start offset is not a valid hex number: " & txtStartOffset, vbInformation
            Exit Sub
        End If
        cmdline = cmdline & " -foff " & txtStartOffset
    End If
    
    If chkfopen.Value = 1 Then
        If Not fso.FileExists(txtFopen.Text) Then
            MsgBox "You must specify a valid file to open", vbInformation
            Exit Sub
        End If
        cmdline = cmdline & " -fopen " & GetShortName(txtFopen)
    End If
                                
    cmdline = cmdline & " -f " & scfile & " " & txtManualArgs
    
    cmdline = "cmd /k chdir /d " & libemu & "\ && " & cmdline
    lastcmdline = cmdline
    
    pid = Shell(cmdline, vbNormalFocus)
    
End Sub

Private Function RecommendedPath() As String
    On Error Resume Next
    RecommendedPath = fso.GetParentFolder(loadedFile)
End Function

Private Function RecommendedName(Optional ext = ".sc") As String
    On Error Resume Next
    RecommendedName = fso.GetBaseName(loadedFile) & ext
End Function
    

Private Sub Form_Load()

    chkApiTable.Value = GetMySetting("apiscan", 0)
    chkCreateDump.Value = GetMySetting("createdump", 0)
    chkInteractiveHooks.Value = GetMySetting("interactive", 0)
    chkReport.Value = GetMySetting("reportmode", 0)
    chkUnlimitedSteps.Value = GetMySetting("unlimitedsteps", 0)
    ChkMemMon.Value = GetMySetting("memorymonitor", 0)
    chkTemp.Value = GetMySetting("apptemp", 0)
    txtManualArgs = GetMySetting("manualargs", "")
    
    If Len(Command) > 0 Then
        c = Replace(Command, """", Empty)
        If fso.FileExists(c) Then
            InitInterface fso.ReadFile(c)
            loadedFile = c
            txtLoadedFile = c
        End If
    End If
    
End Sub

Private Sub Form_Unload(Cancel As Integer)
     Call SaveMySetting("apiscan", chkApiTable.Value)
     Call SaveMySetting("createdump", chkCreateDump.Value)
     Call SaveMySetting("interactive", chkInteractiveHooks.Value)
     Call SaveMySetting("reportmode", chkReport.Value)
     Call SaveMySetting("unlimitedsteps", chkUnlimitedSteps.Value)
     Call SaveMySetting("memorymonitor", ChkMemMon.Value)
     Call SaveMySetting("manualargs", txtManualArgs)
     Call SaveMySetting("apptemp", chkTemp.Value)
End Sub

Private Sub Label6_Click(Index As Integer)
    On Error Resume Next
    Dim b() As Byte
    Dim f As Long
    
    cap = Label6(Index).Caption
    
    If InStr(cap, "Help") > 0 Then
        If checkFor_sctest() Then
            Shell "cmd /k mode con lines=45 cols=100 && """ & sctest & """ -h", vbNormalFocus
        End If
    End If
    
    If InStr(cap, "Home") > 0 Then
        Shell "cmd /c start http://libemu.carnivore.it/"
    End If
    
    If InStr(cap, "Example") > 0 Then
        x = QuickDecode("ACACD13AD13FD4C3C5C5C5610BF38BDCBC49382A79DAC31BEA4E2B6A1A5226A36A26A35A3685A36A22C321A36A1EA56A56A36A16A3FA2B6A16A3E42B6252A3690AA3F42B71361BD71BE07F7FA3E42B263AA951244D5B5B695D2CA31BA9512B5E7E425C5D2CA313ABEA2EABEB2EADE05EF3ADD75EFF2BDC2BD47FC20D2A2A2A5E505E5A084D524D0A05410A1A081A081A081A0A4F4D5E0A5F4148495A411B1C084D524D2A442AC20B2A2A2A5D29EBC2252A2A2A5F4148495A411B1C084D524D2A442AC22F2A2A2A27AEC9D7D7D7EB7273757AABC67E1BEAA3D6A5626AA3FFDB849A6E837F7C79794402442979797D7BD700ABEE7EADEAEB683C793C203C683C0B3C0A3C093C103C0F3C0E3C")
        x = HexStringUnescape(x)
        p = fso.GetFreeFileName(Environ("temp"), ".sc")
        b = StrConv(x, vbFromUnicode, LANG_US)
        f = FreeFile
        Open p For Binary As f
        Put f, , b()
        Close f
        loadedFile = p
        txtLoadedFile = p
        Me.InitInterface CStr(x)
    End If
    
    If InStr(cap, "Demo") > 0 Then
        Shell "cmd /c start http://www.youtube.com/watch?v=jFkegwFasIw"
    End If
    
    If InStr(cap, "scdbg") > 0 Then
        Shell "cmd /c start http://sandsprite.com/blogs/index.php?uid=7&pid=152"
    End If
    
    If InStr(1, cap, "cmdline", 1) > 0 Then
        Clipboard.Clear
        Clipboard.SetText lastcmdline
        MsgBox Len(lastcmdline) & " bytes copied to clipboard" & vbCrLf & vbCrLf & lastcmdline, vbInformation
    End If
    
    
End Sub

Private Sub txtFopen_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, x As Single, Y As Single)
    On Error Resume Next
    txtFopen.Text = Data.Files(1)
    chkfopen.Value = 1
End Sub

Private Sub txtLoadedFile_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, x As Single, Y As Single)
    On Error Resume Next
    txtLoadedFile = Data.Files(1)
    InitInterface fso.ReadFile(txtLoadedFile)
    loadedFile = txtLoadedFile
End Sub
