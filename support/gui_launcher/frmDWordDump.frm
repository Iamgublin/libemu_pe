VERSION 5.00
Begin VB.Form frmDWordDump 
   Caption         =   "Dword Dump (Rop View)"
   ClientHeight    =   7545
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10560
   LinkTopic       =   "Form1"
   ScaleHeight     =   7545
   ScaleWidth      =   10560
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton Command2 
      Caption         =   "Copy All"
      Height          =   375
      Left            =   120
      TabIndex        =   4
      Top             =   300
      Width           =   1395
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Copy Col 3"
      Height          =   375
      Index           =   2
      Left            =   7980
      TabIndex        =   3
      Top             =   300
      Width           =   1395
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Copy Col 2"
      Height          =   375
      Index           =   1
      Left            =   4980
      TabIndex        =   2
      Top             =   300
      Width           =   1395
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Copy Col 1"
      Height          =   375
      Index           =   0
      Left            =   2340
      TabIndex        =   1
      Top             =   300
      Width           =   1395
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   12
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   6735
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   0
      Top             =   660
      Width           =   10335
   End
End
Attribute VB_Name = "frmDWordDump"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByRef Destination As Long, ByRef Source As Byte, ByVal Length As Long)

Dim a() As String
Dim b() As String
Dim c() As String
    
    

Private Sub push(ary, Value) 'this modifies parent ary object
    On Error GoTo init
    Dim x As Long
    x = UBound(ary) '<-throws Error If Not initalized
    ReDim Preserve ary(UBound(ary) + 1)
    ary(UBound(ary)) = Value
    Exit Sub
init: ReDim ary(0): ary(0) = Value
End Sub

Function pad(x As String, Optional min As Long = 30)
   sz = min - Len(x)
    If sz > 0 Then
        pad = x & Space(sz)
    Else
        pad = x
    End If
End Function

Function DumpFile(fpath As String)
    
    On Error Resume Next
    
    Dim foff As String
    Dim ret() As String
    
    header = "fileoff         offset 1        offset 2        offset 3"
    
    a() = DumpAsDWords(fpath, 0) 'longest
    b() = DumpAsDWords(fpath, 1)
    c() = DumpAsDWords(fpath, 2) 'shortest
    
    ReDim ret(UBound(a))
    
    For i = 0 To UBound(a)
        foff = Hex(i * 4)
        While Len(foff) < 8
            foff = "0" & foff
        Wend
        ret(i) = foff & vbTab & a(i)
        If i < UBound(c) Then
            ret(i) = ret(i) & vbTab & b(i) & vbTab & c(i)
        Else
            If i < UBound(b) Then ret(i) = ret(i) & vbTab & b(i)
            
        End If
    Next
        
    Text1 = header & vbCrLf & String(56, "-") & vbCrLf & Join(ret, vbCrLf)
    Me.Visible = True
    
End Function

Private Function DumpAsDWords(fpath As String, ByVal startOffset As Long) As String()

    Dim b() As Byte
    Dim l As Long
    Dim i As Long
    Dim ret() As String
    Dim m As String
    Dim hits As Long
    
    startOffset = startOffset + 1
    
    f = FreeFile
    Open fpath For Binary As f
    ReDim b(LOF(f) - startOffset)
    Get f, startOffset, b()
    Close f
    
    For i = 0 To UBound(b) Step 4
        CopyMemory l, b(i), 4
        tmp = Hex(l)
        While Len(tmp) <> 8
            tmp = "0" & tmp
        Wend
        push ret, tmp
    Next
    
    DumpAsDWords = ret()

End Function

Private Sub Command1_Click(Index As Integer)
    Dim ary() As String
    
    Select Case Index
        Case 0: ary = a
        Case 1: ary = b
        Case 2: ary = c
    End Select
        
    Clipboard.Clear
    Clipboard.SetText Join(ary, vbCrLf)
    
End Sub

Private Sub Command2_Click()
    Clipboard.Clear
    Clipboard.SetText Text1
End Sub

Private Sub Form_Resize()
    On Error Resume Next
    With Me
        Text1.Width = .Width - Text1.Left - 200
        Text1.Height = .Height - Text1.Top - 200
    End With
End Sub
