VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "MSCOMCTL.OCX"
Begin VB.Form fHarmony 
   Caption         =   "Harmony Hash API Lookup"
   ClientHeight    =   6000
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10770
   LinkTopic       =   "Form1"
   ScaleHeight     =   6000
   ScaleWidth      =   10770
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton cmdCopy 
      Caption         =   "Copy"
      Height          =   255
      Left            =   9480
      TabIndex        =   4
      Top             =   60
      Width           =   1095
   End
   Begin VB.TextBox Text2 
      Height          =   2295
      Left            =   60
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   3
      Top             =   3600
      Width           =   10575
   End
   Begin MSComctlLib.ListView lv 
      Height          =   3195
      Left            =   120
      TabIndex        =   2
      Top             =   360
      Width           =   10515
      _ExtentX        =   18547
      _ExtentY        =   5636
      View            =   3
      MultiSelect     =   -1  'True
      LabelWrap       =   -1  'True
      HideSelection   =   -1  'True
      FullRowSelect   =   -1  'True
      GridLines       =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   -2147483643
      BorderStyle     =   1
      Appearance      =   1
      NumItems        =   4
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "Hash"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "Dll"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(3) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   2
         Text            =   "function"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(4) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   3
         Text            =   "Args"
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.TextBox Text1 
      Height          =   315
      Left            =   780
      TabIndex        =   1
      Top             =   0
      Width           =   8415
   End
   Begin VB.Label Label1 
      Caption         =   "Search"
      Height          =   255
      Left            =   60
      TabIndex        =   0
      Top             =   60
      Width           =   1035
   End
End
Attribute VB_Name = "fHarmony"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim cn As New Connection
Dim selli As ListItem

Private Sub Command1_Click()
    Dim li As ListItem
    Dim rs As Recordset
    Dim rs2 As Recordset
    
    lv.ListItems.Clear
    Set rs = cn.Execute("Select * from hashs where function like '%" & Text1 & "%'")
    
    While Not rs.EOF
        Set li = lv.ListItems.Add(, , rs!hash)
        li.SubItems(1) = rs!library
        li.SubItems(2) = rs!function
        tmp = rs!function
        If VBA.Right(tmp, 1) = "A" Or VBA.Right(tmp, 1) = "W" Then tmp = Mid(tmp, 1, Len(tmp) - 1)
        Set rs2 = cn.Execute("Select * from tbldeclares where name='" & tmp & "'")
        If Not rs2.EOF And Not rs2.BOF Then
            tmp = rs2!declare
            a = InStr(tmp, "(")
            If a > 0 Then tmp = Mid(tmp, a)
            li.SubItems(3) = tmp
        End If
        rs.MoveNext
    Wend
    
    
End Sub

Private Sub cmdCopy_Click()
    Clipboard.Clear
    Clipboard.SetText Text2
    MsgBox Len(Text2) & " bytes copied"
End Sub

Private Sub Form_Load()
    On Error Resume Next
    Dim db As String
    db = App.Path & "\harmony.mdb"
    cn.ConnectionString = "Driver={Microsoft Access Driver (*.mdb)};Dbq=" & db & ";Uid=Admin;Pwd=;"
    cn.Open
    
    lv.ColumnHeaders(lv.ColumnHeaders.Count).Width = lv.Width - lv.ColumnHeaders(lv.ColumnHeaders.Count).Left
    'Dim fso As New CFileSystem2
    'tmp = fso.ReadFile("C:\Program Files\Microsoft Visual Studio\Common\Tools\Winapi\declares.txt")
    'tmp = Split(tmp, vbCrLf)
    'For Each x In tmp
    '    cn.Execute "Insert into tblDeclares(declare) values('" & x & "')"
    'Next
    'MsgBox "done"
    
    'Dim rs As Recordset
    'tt = 0
    'Set rs = cn.Execute("Select * from tbldeclares")
    'While Not rs.EOF
    '    x = rs!declare
    '    a = InStr(x, " ")
     '   If a > 0 Then
    '        x = Mid(x, 1, a)
    '        cn.Execute "Update tbldeclares set name='" & x & "' where id=" & rs!id
    '        tt = tt + 1
    '    End If
    '    rs.MoveNext
    'Wend
    'MsgBox "done records " & tt
    
End Sub

Private Sub lv_DblClick()
    If selli Is Nothing Then
        Dim li As ListItem
        For Each li In lv.ListItems
            If li.Selected = True Then Set selli = li
        Next
    End If
    
    If selli Is Nothing Then Exit Sub
    
    On Error Resume Next
    X = Split(selli.SubItems(3), ",")
    For i = UBound(X) To 0 Step -1
        tmp = tmp & "  push " & vbTab & "; " & X(i) & vbCrLf
    Next
    Text2 = Text2 & tmp & "  push " & selli.Text & vbTab & ";  " & selli.SubItems(2) & vbCrLf & vbCrLf
End Sub

Private Sub lv_ItemClick(ByVal Item As MSComctlLib.ListItem)
    Set selli = Item
End Sub

Private Sub lv_KeyDown(KeyCode As Integer, Shift As Integer)
    If KeyCode = 13 Then lv_DblClick
End Sub

Private Sub Text1_Change()
    If Len(Text1.Text) > 3 Then Command1_Click
End Sub
