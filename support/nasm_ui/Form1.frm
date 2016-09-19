VERSION 5.00
Object = "{3B7C8863-D78F-101B-B9B5-04021C009402}#1.2#0"; "RICHTX32.OCX"
Begin VB.Form Form1 
   Caption         =   "Form1"
   ClientHeight    =   7830
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   11610
   LinkTopic       =   "Form1"
   ScaleHeight     =   7830
   ScaleWidth      =   11610
   StartUpPosition =   3  'Windows Default
   Begin VB.CheckBox chkCygWin 
      Caption         =   "cygwin vers"
      Height          =   195
      Left            =   5715
      TabIndex        =   12
      Top             =   5355
      Width           =   1410
   End
   Begin VB.TextBox txtExt 
      Height          =   285
      Left            =   4800
      TabIndex        =   11
      Text            =   ".sc"
      Top             =   5520
      Width           =   855
   End
   Begin VB.CommandButton Command6 
      Caption         =   "Copy Wrapped"
      Height          =   255
      Left            =   8520
      TabIndex        =   9
      Top             =   5760
      Width           =   1575
   End
   Begin RichTextLib.RichTextBox dev 
      Height          =   5295
      Left            =   60
      TabIndex        =   8
      Top             =   60
      Width           =   11475
      _ExtentX        =   20241
      _ExtentY        =   9340
      _Version        =   393217
      Enabled         =   -1  'True
      ScrollBars      =   3
      TextRTF         =   $"Form1.frx":0000
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Courier"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
   End
   Begin VB.CommandButton Command5 
      Caption         =   "Manual"
      Height          =   315
      Left            =   9660
      TabIndex        =   7
      Top             =   5460
      Width           =   975
   End
   Begin VB.CommandButton Command4 
      Caption         =   "Harmony"
      Height          =   315
      Left            =   8460
      TabIndex        =   6
      Top             =   5460
      Width           =   1035
   End
   Begin VB.CommandButton Command3 
      Caption         =   "Olly"
      Height          =   315
      Left            =   7320
      TabIndex        =   5
      Top             =   5460
      Width           =   1095
   End
   Begin VB.CommandButton Command2 
      Caption         =   "ScDbg"
      Height          =   270
      Left            =   6240
      TabIndex        =   4
      Top             =   5595
      Width           =   1035
   End
   Begin VB.TextBox txtFile 
      Height          =   315
      Left            =   360
      OLEDropMode     =   1  'Manual
      TabIndex        =   2
      Top             =   5460
      Width           =   3855
   End
   Begin VB.TextBox Text1 
      Height          =   1875
      Left            =   60
      MultiLine       =   -1  'True
      OLEDropMode     =   1  'Manual
      ScrollBars      =   2  'Vertical
      TabIndex        =   1
      Top             =   5880
      Width           =   11535
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Assemble"
      Height          =   375
      Left            =   10800
      TabIndex        =   0
      Top             =   5460
      Width           =   795
   End
   Begin VB.Label Label2 
      Caption         =   "Ext"
      Height          =   255
      Left            =   4440
      TabIndex        =   10
      Top             =   5520
      Width           =   495
   End
   Begin VB.Label Label1 
      Caption         =   "File"
      Height          =   255
      Left            =   60
      TabIndex        =   3
      Top             =   5520
      Width           =   495
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim fso As New CFileSystem2
Dim wsh As New WshShell

Private Declare Function ShellExecute Lib "shell32.dll" Alias "ShellExecuteA" (ByVal hwnd As Long, ByVal lpOperation As String, ByVal lpFile As String, ByVal lpParameters As String, ByVal lpDirectory As String, ByVal nShowCmd As Long) As Long


Const sc = "c:\nasm\test.sc"

Private Sub Command1_Click()
    On Error Resume Next
    If Not fso.FileExists(txtFile) Then
        MsgBox "no file loaded"
        Exit Sub
    End If
    fso.WriteFile txtFile, dev.Text
    cmd = "c:\nasm\nasm.exe -f bin -O3 -o c:\nasm\test.sc """ & txtFile & """"
    Dim ts As TextStream
    Text1 = Replace(wsh.Exec(cmd).StdErr.ReadAll(), txtFile, Empty)
    If fso.FileExists(sc) Then Text1 = Hexdump(fso.ReadFile(sc), 1)
    pf = fso.GetParentFolder(txtFile)
    bn = fso.GetBaseName(txtFile)
    new_sc = pf & "\" & bn & txtExt '".sc"
    If fso.FileExists(CStr(new_sc)) Then Kill new_sc
    FileCopy sc, new_sc
    Me.Caption = "Size: 0x" & Hex(Len(Text1) / 2)
    GenerateExe
    If fso.FileExists(pf & "\shellcode.exe_") Then Kill pf & "\shellcode.exe_"
    FileCopy App.Path & "\shellcode.exe_", pf & "\shellcode.exe_"
End Sub

Private Sub Command2_Click()
    On Error Resume Next
    If Not fso.FileExists(sc) Then
        MsgBox "sc file not found"
        Exit Sub
    End If
    If chkCygWin.value = 1 Then
        FileCopy sc, "D:\_code\libemu\git_libemu\bin\test.sc"
        Shell "cmd /k D:\_code\libemu\git_libemu\bin\scdbg.exe -f D:\_code\libemu\git_libemu\bin\test.sc -vvv", vbNormalFocus
    Else
        FileCopy sc, "D:\_code\libemu\VS_LIBEMU\test.sc"
        Shell "cmd /k D:\_code\libemu\VS_LIBEMU\scdbg.exe -f D:\_code\libemu\VS_LIBEMU\test.sc -vvv -i -e 3", vbNormalFocus
    End If
End Sub

Private Sub Command3_Click()
    On Error Resume Next
    
    If Not fso.FileExists(sc) Then
        MsgBox "sc file not found"
        Exit Sub
    End If
    
    GenerateExe
    pth = App.Path & "\shellcode.exe_"
    Shell "C:\tools\odbg110\OLLYDBG.EXE """ & pth & """", vbNormalFocus

End Sub

Sub GenerateExe()

    If Not fso.FileExists(sc) Then
        MsgBox "sc file not found"
        Exit Sub
    End If
    
    Dim f As Long
    pth = App.Path & "\shellcode.exe_"
    Dim b() As Byte
    
    f = FreeFile
    Open sc For Binary As f
    ReDim b(LOF(f))
    Get f, , b()
    Close f
    
    Open pth For Binary As f
    Put f, &H1000 + 1, b()
    Close
End Sub
Private Sub Command4_Click()
    frmharmony.Show
End Sub

Private Sub Command5_Click()
    On Error Resume Next
    ShellExecute 0, "open", "c:\nasm\nasmdoc.pdf", "", "", 1
End Sub

Private Sub Command6_Click()
  On Error GoTo hell
    
    Dim wrapat As Long
    Dim startat As Long
    Dim tmp()
    
    wrapat = 60
    startat = 1
    X = Replace(Text1, vbCrLf, "")
    Do While 1
        If startat + wrapat > Len(X) Then
            wrapat = Len(X) - startat
            If wrapat > 0 Then
                push tmp, Mid(X, startat)
            End If
            Exit Do
        Else
            b = Mid(X, startat, wrapat)
            push tmp, b
            startat = startat + wrapat
        End If
    Loop
    
    Text1 = Join(tmp, vbCrLf)
    Clipboard.Clear
    Clipboard.SetText Text1
    
    MsgBox Hex(Len(X)) & "=" & Hex(Len(Join(tmp, ""))) & " copied to clipboard", vbInformation
    
Exit Sub
hell:
    MsgBox Err.Description
    
    
End Sub

 

Private Sub Form_Load()
    If Len(Command) > 0 Then
        txtFile = Replace(Command, """", Empty)
        dev.Text = fso.ReadFile(txtFile)
    End If
End Sub

Private Sub Text1_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    On Error Resume Next
    Text1 = Hexdump(fso.ReadFile(Data.Files(1)), 1)
End Sub

Private Sub txtFile_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    txtFile = Data.Files(1)
    dev.Text = fso.ReadFile(txtFile)
End Sub


Function Hexdump(ByVal str, Optional hexOnly = 0) As String
    Dim s() As String, chars As String, tmp As String
    On Error Resume Next
    Dim ary() As Byte
    Dim offset As Long
    
    offset = 0
    str = " " & str
    ary = StrConv(str, vbFromUnicode)
    
    chars = "   "
    For i = 1 To UBound(ary)
        tt = Hex(ary(i))
        If Len(tt) = 1 Then tt = "0" & tt
        tmp = tmp & tt & " "
        X = ary(i)
        chars = chars & IIf((X > 32 And X < 127) Or X > 191, Chr(X), ".")
        If i > 1 And i Mod 16 = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            If hexOnly = 0 Then
                push s, h & "   " & tmp & chars
            Else
                push s, tmp
            End If
            offset = offset + 16
            tmp = Empty
            chars = "   "
        End If
    Next
    
    If tmp <> Empty Then
        If hexOnly = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            h = h & "   " & tmp
            While Len(h) <= 56: h = h & " ": Wend
            push s, h & chars
        Else
            push s, tmp
        End If
    End If
    
    Hexdump = Join(s, vbCrLf)
    
    If hexOnly <> 0 Then
        Hexdump = Replace(Hexdump, " ", "")
        Hexdump = Replace(Hexdump, vbCrLf, "")
    End If
    
End Function

Private Sub push(ary, value)    'his modifies parent ary object
    On Error GoTo init
    X = UBound(ary) '<-throws Error If Not initalized
    ReDim Preserve ary(UBound(ary) + 1)
    ary(UBound(ary)) = value
    Exit Sub
init: ReDim ary(0): ary(0) = value
End Sub




