VERSION 5.00
Object = "{3B7C8863-D78F-101B-B9B5-04021C009402}#1.2#0"; "RICHTX32.OCX"
Begin VB.Form Form1 
   Caption         =   "Form1"
   ClientHeight    =   4995
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   13860
   LinkTopic       =   "Form1"
   ScaleHeight     =   4995
   ScaleWidth      =   13860
   StartUpPosition =   3  'Windows Default
   Begin VB.CheckBox chkWriteAsFile 
      Caption         =   "Write to out.txt"
      Height          =   195
      Left            =   8460
      TabIndex        =   7
      Top             =   360
      Width           =   2895
   End
   Begin VB.CommandButton Command4 
      Caption         =   "Prepare raw lordpe export list"
      Height          =   465
      Left            =   11655
      TabIndex        =   6
      Top             =   45
      Width           =   2130
   End
   Begin RichTextLib.RichTextBox rtf 
      Height          =   4335
      Left            =   60
      TabIndex        =   4
      Top             =   540
      Width           =   13755
      _ExtentX        =   24262
      _ExtentY        =   7646
      _Version        =   393217
      ScrollBars      =   2
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
   Begin VB.TextBox Text3 
      Height          =   315
      Left            =   6960
      TabIndex        =   3
      Text            =   "7C800000"
      Top             =   120
      Width           =   1395
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Get Hex Data as C commented src"
      Height          =   285
      Left            =   8415
      TabIndex        =   1
      Top             =   45
      Width           =   3060
   End
   Begin VB.TextBox Text1 
      Height          =   315
      Left            =   60
      OLEDropMode     =   1  'Manual
      TabIndex        =   0
      Text            =   "drag and drop file here"
      Top             =   120
      Width           =   6015
   End
   Begin VB.CommandButton Command3 
      Caption         =   "rva w/lordpe csv"
      Height          =   435
      Left            =   45
      TabIndex        =   5
      Top             =   585
      Visible         =   0   'False
      Width           =   1575
   End
   Begin VB.Label Label1 
      Caption         =   "Base"
      Height          =   315
      Left            =   6360
      TabIndex        =   2
      Top             =   120
      Width           =   495
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Private Sub Command1_Click()
    
    On Error Resume Next
    Dim f As Long
    Dim f2 As Long, fp As String, dat As String
    Dim offset As Long
    Dim b(15) As Byte
    Dim b2() As Byte
    Dim tmp() As String
    
    f = FreeFile
    rtf.Text = Empty
    offset = CLng("&h" & Text3)
    Open Text1 For Binary As f
    
    f2 = FreeFile
    fp = App.Path & "\out.txt"
    If chkWriteAsFile.Value = 1 Then
        Kill fp
        Open fp For Binary As f2
    End If
    
again:
    Get f, , b()
    dat = Hexdump(StrConv(b, vbUnicode), , offset) & vbCrLf
    
    If chkWriteAsFile.Value = 1 Then
        b2() = StrConv(dat, vbFromUnicode, 1033)
        Put f2, , b2()
    Else
        push tmp, dat
    End If
    
    If offset Mod 1600 = 0 Then
        DoEvents
        Me.Caption = Hex(offset) & " / " & Hex(LOF(f))
        Me.Refresh
    End If
    
    'offset = offset + 16 '<--hexdump already increments _byref_ offset on its own..
If Not EOF(f) Then GoTo again
    
    Close f
    Close f2
    
    If chkWriteAsFile.Value = 0 Then
        rtf.Text = Join(tmp, "")
    End If
    
    MsgBox "done"
    
End Sub


Private Sub Command3_Click()
    
    Dim f As Long
    Dim b() As Byte
    Dim s
    
    f = FreeFile
    Open Text1 For Binary As f
    ReDim b(LOF(f))
    Get f, , b()
    Close f
    
    s = StrConv(b, vbUnicode)
    s = Split(s, vbCrLf)
    For Each X In s
        If Len(X) > 0 And InStr(X, ",") > 0 And InStr(X, "n/a") < 1 Then
            csv = Split(X, ",") 'ordial,rva,name
            '{"getpeername", 0x00010B50, NULL, NULL},
            tmp = tmp & "{""" & csv(2) & """, " & csv(1) & ", NULL, NULL}," & vbCrLf
        End If
    Next
    
    rtf.Text = tmp
    
End Sub

Private Sub Command4_Click()
    Dim f As Long
    Dim b() As Byte
    Dim s
    
    f = FreeFile
    Open Text1 For Binary As f
    ReDim b(LOF(f))
    Get f, , b()
    Close f
    
    s = StrConv(b, vbUnicode)
    
    s = Replace(s, "   ", Empty)
    s = Replace(s, "  ", " ")
    s = Replace(s, " ", ",")
    s = Replace(s, """", "")
    s = Split(s, vbCrLf)
    For Each X In s
        If Len(X) > 0 And InStr(X, ",") > 0 Then
            csv = Split(X, ",") 'ordial,rva,name
            '{"getpeername", 0x00010B50, NULL, NULL},
            If csv(2) = "n/a" Then csv(2) = ""
            tmp = tmp & "{""" & csv(2) & """, " & csv(1) & ", NULL, NULL, " & csv(0) & " }," & vbCrLf
        End If
    Next
    
    rtf.Text = tmp
End Sub

Private Sub Text1_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    On Error Resume Next
    Text1 = Data.Files(1)
End Sub


Function Hexdump(ByVal str As String, Optional hexOnly = 0, Optional offset = 0) As String
    Dim s() As String, chars As String, tmp As String
    On Error Resume Next
    Dim ary() As Byte
 
    
    str = " " & str
    ary = StrConv(str, vbFromUnicode)
    
    chars = "   //"
    For i = 1 To UBound(ary)
        tt = Hex(ary(i))
        If Len(tt) = 1 Then tt = "0" & tt
        tmp = tmp & "\x" & tt
        X = ary(i)
        chars = chars & IIf((X > 32 And X < 127) Or X > 191, Chr(X), ".")
        If i > 1 And i Mod 16 = 0 Then
            h = Hex(offset)
            While Len(h) < 6: h = "0" & h: Wend
            If hexOnly = 0 Then
                push s, "/* " & h & " */   """ & tmp & """" & chars
            Else
                push s, tmp
            End If
            offset = offset + 16
            tmp = """"
            chars = "   //"
        End If
    Next
    
    If tmp <> Empty And tmp <> """" Then
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

Private Sub push(ary, Value)    'his modifies parent ary object
    On Error GoTo init
    X = UBound(ary) '<-throws Error If Not initalized
    ReDim Preserve ary(UBound(ary) + 1)
    ary(UBound(ary)) = Value
    Exit Sub
init: ReDim ary(0): ary(0) = Value
End Sub


