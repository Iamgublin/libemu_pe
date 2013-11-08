VERSION 5.00
Begin VB.Form frmScTest 
   Caption         =   "scDbg - libemu Shellcode Logger Launch Interface"
   ClientHeight    =   7485
   ClientLeft      =   60
   ClientTop       =   630
   ClientWidth     =   10140
   Icon            =   "frmScTest.frx":0000
   LinkTopic       =   "Form3"
   ScaleHeight     =   7485
   ScaleWidth      =   10140
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdLoadFile 
      Caption         =   "..."
      Height          =   315
      Left            =   9240
      TabIndex        =   21
      Top             =   60
      Width           =   795
   End
   Begin VB.TextBox txtLoadedFile 
      Height          =   315
      Left            =   1260
      Locked          =   -1  'True
      OLEDropMode     =   1  'Manual
      TabIndex        =   20
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
      Height          =   4740
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   3
      Top             =   2700
      Width           =   9960
   End
   Begin VB.Frame Frame1 
      Caption         =   " Options "
      Height          =   2115
      Left            =   60
      TabIndex        =   0
      Top             =   480
      Width           =   10005
      Begin VB.TextBox txtProcCmdLine 
         Height          =   285
         Left            =   2280
         TabIndex        =   25
         Top             =   1020
         Width           =   5475
      End
      Begin VB.CheckBox chkCmdLine 
         Caption         =   "Process Command Line"
         Height          =   255
         Left            =   240
         TabIndex        =   24
         Top             =   1020
         Width           =   1995
      End
      Begin VB.CheckBox chkNoRW 
         Caption         =   "No RW Display"
         Height          =   195
         Left            =   240
         TabIndex        =   22
         Top             =   720
         Width           =   1395
      End
      Begin VB.TextBox txtManualArgs 
         Height          =   285
         Left            =   1800
         TabIndex        =   18
         Top             =   1680
         Width           =   5955
      End
      Begin VB.TextBox txtStartOffset 
         Height          =   285
         Left            =   8160
         TabIndex        =   15
         Text            =   "0"
         Top             =   180
         Width           =   675
      End
      Begin VB.CheckBox chkOffset 
         Caption         =   "Start Offset  0x"
         Height          =   255
         Left            =   6780
         TabIndex        =   16
         Top             =   180
         Width           =   1515
      End
      Begin VB.CommandButton cmdrowse 
         Caption         =   "..."
         Height          =   285
         Left            =   7830
         TabIndex        =   14
         Top             =   1380
         Width           =   465
      End
      Begin VB.TextBox txtFopen 
         Height          =   285
         Left            =   1035
         OLEDropMode     =   1  'Manual
         TabIndex        =   13
         Top             =   1380
         Width           =   6720
      End
      Begin VB.CheckBox chkfopen 
         Caption         =   "fopen"
         Height          =   240
         Left            =   240
         TabIndex        =   12
         Top             =   1380
         Width           =   1230
      End
      Begin VB.CheckBox ChkMemMon 
         Caption         =   "Monitor DLL Read/Write"
         Height          =   195
         Left            =   1920
         TabIndex        =   11
         Top             =   720
         Width           =   2295
      End
      Begin VB.CheckBox chkFindSc 
         Caption         =   "FindSc"
         Height          =   255
         Left            =   5640
         TabIndex        =   10
         Top             =   180
         Width           =   1095
      End
      Begin VB.CheckBox chkDebugShell 
         Caption         =   "Debug Shell"
         Height          =   195
         Left            =   4080
         TabIndex        =   9
         Top             =   480
         Width           =   1455
      End
      Begin VB.CheckBox chkUnlimitedSteps 
         Caption         =   "Unlimited steps"
         Height          =   255
         Left            =   4080
         TabIndex        =   8
         Top             =   180
         Width           =   1635
      End
      Begin VB.CheckBox chkApiTable 
         Caption         =   "Scan for Api table"
         Height          =   195
         Left            =   1920
         TabIndex        =   7
         Top             =   180
         Width           =   1995
      End
      Begin VB.CheckBox chkInteractiveHooks 
         Caption         =   "Use Interactive Hooks"
         Height          =   255
         Left            =   1920
         TabIndex        =   6
         Top             =   420
         Width           =   1935
      End
      Begin VB.CheckBox chkCreateDump 
         Caption         =   "Create Dump"
         Height          =   255
         Left            =   240
         TabIndex        =   5
         Top             =   420
         Width           =   1455
      End
      Begin VB.CommandButton Command1 
         Caption         =   "Launch"
         Height          =   375
         Left            =   8370
         TabIndex        =   2
         Top             =   1680
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
      Begin VB.Label Label3 
         Appearance      =   0  'Flat
         BackColor       =   &H80000005&
         BorderStyle     =   1  'Fixed Single
         Caption         =   "     More"
         ForeColor       =   &H00FF0000&
         Height          =   255
         Left            =   9060
         TabIndex        =   23
         Top             =   600
         Width           =   855
      End
      Begin VB.Label Label1 
         Caption         =   "Manual  Arguments"
         Height          =   285
         Left            =   225
         TabIndex        =   17
         Top             =   1740
         Width           =   1410
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
         Left            =   9120
         TabIndex        =   4
         Top             =   240
         Width           =   735
      End
   End
   Begin VB.Label Label2 
      Caption         =   "Shellcode file"
      Height          =   255
      Left            =   120
      TabIndex        =   19
      Top             =   120
      Width           =   1035
   End
   Begin VB.Menu mnuPopup 
      Caption         =   "mnuPopup"
      Begin VB.Menu mnuMore 
         Caption         =   "Show Help"
         Index           =   0
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Show Hooks"
         Index           =   1
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Show Signatures"
         Index           =   2
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Show Signatures (w/ Disasm)"
         Index           =   3
      End
      Begin VB.Menu mnuMore 
         Caption         =   "-"
         Index           =   4
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Copy Last Command Line"
         Index           =   5
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Directory Scan Mode"
         Index           =   6
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Directory Scan (Single Report)"
         Index           =   7
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Highlighted Dump"
         Index           =   8
      End
      Begin VB.Menu mnuMore 
         Caption         =   "-"
         Index           =   9
      End
      Begin VB.Menu mnuMore 
         Caption         =   "scDbg Homepage"
         Index           =   10
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Libemu Homepage"
         Index           =   11
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Video Trainer 1"
         Index           =   12
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Video Trainer 2"
         Index           =   13
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Get Source (Windows)"
         Index           =   14
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Get Source (Linux/Cygwin)"
         Index           =   15
      End
      Begin VB.Menu mnuMore 
         Caption         =   "-"
         Index           =   16
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Disasm Buffer (uses start offset)"
         Index           =   17
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Register .sc File Extension"
         Index           =   18
      End
      Begin VB.Menu mnuMore 
         Caption         =   "Dword Dump (Rop View)"
         Index           =   19
      End
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
    If chkNoRW.Value = 1 Then cmdline = cmdline & " -norw" '" -temp " & GetShortName(fso.GetParentFolder(loadedFile))
    If chkCmdLine.Value = 1 Then cmdline = cmdline & " -cmd """ & Replace(txtProcCmdLine, """", "\""") & """"
    
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

    mnuPopup.Visible = False
    chkApiTable.Value = GetMySetting("apiscan", 0)
    chkCreateDump.Value = GetMySetting("createdump", 0)
    chkInteractiveHooks.Value = GetMySetting("interactive", 0)
    chkReport.Value = GetMySetting("reportmode", 0)
    chkUnlimitedSteps.Value = GetMySetting("unlimitedsteps", 0)
    ChkMemMon.Value = GetMySetting("memorymonitor", 0)
    chkNoRW.Value = GetMySetting("norw", 0)
    txtManualArgs = GetMySetting("manualargs", "")
    txtProcCmdLine = GetMySetting("txtcmdline", "")
    
    Call checkFor_sctest
    
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
     Call SaveMySetting("norw", chkNoRW.Value)
     Call SaveMySetting("txtcmdline", txtProcCmdLine)
End Sub

Private Sub Label3_Click()
    PopupMenu mnuPopup
End Sub

Private Sub Label6_Click(Index As Integer)
    On Error Resume Next
    Dim b() As Byte
    Dim f As Long
    
    cap = Label6(Index).Caption
    
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

End Sub


Private Sub mnuMore_Click(Index As Integer)

    Dim homedir As String
    
    homedir = GetShortName(fso.GetParentFolder(sctest))
    cmd = "cmd /k chdir /d " & homedir & "\ && "
    cmd = cmd & "mode con lines=45 cols=100 && """ & sctest & """ "
    
    Select Case Index
        Case 0: cmd = cmd & "-h"
        Case 1: cmd = cmd & "-hooks"
        Case 2: cmd = cmd & "-sigs"
        Case 3: cmd = cmd & "-sigs -disasm"
        Case 4: 'divider
        Case 5:
                Clipboard.Clear
                Clipboard.SetText lastcmdline
                MsgBox Len(lastcmdline) & " bytes copied to clipboard" & vbCrLf & vbCrLf & lastcmdline, vbInformation
                Exit Sub
        Case 6, 7:
                d = dlg.FolderDialog()
                If Len(d) = 0 Then Exit Sub
                cmd = cmd & "-dir " & GetShortName(CStr(d))
                If Index = 7 Then cmd = cmd & " -r"
                
        Case 8:
                If Not fso.FileExists(txtLoadedFile) Then
                    MsgBox "No shellcode file loaded yet.", vbInformation
                    Exit Sub
                End If
                cmd = cmd & "-f " & GetShortName(txtLoadedFile) & " -dump"
                
        Case 9: 'divider
        Case 10: cmd = "cmd /c start http://sandsprite.com/blogs/index.php?uid=7&pid=152"
        Case 11: cmd = "cmd /c start http://libemu.carnivore.it/"
        Case 12: cmd = "cmd /c start http://www.youtube.com/watch?v=jFkegwFasIw"
        Case 13: cmd = "cmd /c start http://www.youtube.com/watch?v=qkDPUF3bf6E"
        Case 14: cmd = "cmd /c start https://github.com/dzzie/VS_LIBEMU"
        Case 15: cmd = "cmd /c start https://github.com/dzzie/SCDBG"
        Case 17:
                If Not fso.FileExists(txtLoadedFile) Then
                    MsgBox "No shellcode file loaded yet.", vbInformation
                    Exit Sub
                End If
                cmd = cmd & "-f " & GetShortName(txtLoadedFile) & " -disasm 200 -foff " & txtStartOffset.Text
                
        Case 18:
                homedir = homedir & "\gui_launcher.exe"
                If Not fso.FileExists(homedir) Then Exit Sub
                cmd = "cmd /c ftype Shellcode.Document=""" & homedir & """ %1 && assoc .sc=Shellcode.Document"
                
        Case 19:
                If Not fso.FileExists(txtLoadedFile) Then
                    MsgBox "No shellcode file loaded yet.", vbInformation
                    Exit Sub
                End If
                
                frmDWordDump.DumpFile txtLoadedFile
                Exit Sub
                
    End Select
    
    lastcmdline = cmd
    
    On Error Resume Next
    Shell cmd, vbNormalFocus
    
    If Index = 18 Then 'register file type, set default icon..
        Dim wsh As Object 'WshShell
        Set wsh = CreateObject("WScript.Shell")
        If Not wsh Is Nothing Then
            wsh.RegWrite "HKCR\Shellcode.Document\DefaultIcon\", homedir & ",0"
        End If
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
