VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form3 
   Caption         =   "Form3"
   ClientHeight    =   4890
   ClientLeft      =   60
   ClientTop       =   630
   ClientWidth     =   10890
   LinkTopic       =   "Form3"
   ScaleHeight     =   4890
   ScaleWidth      =   10890
   StartUpPosition =   2  'CenterScreen
   Begin VB.CommandButton cmdLoad 
      Caption         =   "Parse"
      Height          =   375
      Left            =   8040
      TabIndex        =   10
      Top             =   390
      Width           =   1125
   End
   Begin VB.TextBox txtPass 
      Height          =   285
      Left            =   6840
      TabIndex        =   8
      Top             =   0
      Width           =   1455
   End
   Begin VB.TextBox txtUrl 
      Height          =   285
      Left            =   840
      TabIndex        =   7
      Top             =   0
      Width           =   4935
   End
   Begin VB.CheckBox chkProcessed 
      Caption         =   "Mark Processed"
      Height          =   255
      Left            =   9330
      TabIndex        =   4
      Top             =   60
      Width           =   1575
   End
   Begin MSComctlLib.ListView lv 
      Height          =   3975
      Left            =   0
      TabIndex        =   3
      Top             =   840
      Width           =   10815
      _ExtentX        =   19076
      _ExtentY        =   7011
      View            =   3
      LabelEdit       =   1
      MultiSelect     =   -1  'True
      LabelWrap       =   -1  'True
      HideSelection   =   0   'False
      FullRowSelect   =   -1  'True
      GridLines       =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   -2147483643
      BorderStyle     =   1
      Appearance      =   1
      NumItems        =   5
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "ID"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "Status"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(3) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   2
         Text            =   "Size"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(4) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   3
         Text            =   "Url"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(5) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   4
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Upload"
      Height          =   375
      Left            =   9270
      TabIndex        =   2
      Top             =   390
      Width           =   1575
   End
   Begin VB.TextBox Text1 
      Height          =   375
      Left            =   960
      TabIndex        =   1
      Top             =   360
      Width           =   6945
   End
   Begin VB.Label Label8 
      Caption         =   "?"
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
      Left            =   8400
      TabIndex        =   9
      Top             =   0
      Width           =   255
   End
   Begin VB.Label Label2 
      Caption         =   "Password:"
      Height          =   255
      Index           =   1
      Left            =   5880
      TabIndex        =   6
      Top             =   0
      Width           =   855
   End
   Begin VB.Label Label2 
      Caption         =   "WebScript:"
      Height          =   255
      Index           =   0
      Left            =   0
      TabIndex        =   5
      Top             =   0
      Width           =   975
   End
   Begin VB.Label Label1 
      Caption         =   "CSV ID List"
      Height          =   255
      Left            =   0
      TabIndex        =   0
      Top             =   360
      Width           =   975
   End
   Begin VB.Menu mnuTools 
      Caption         =   "Tools"
      Begin VB.Menu mnuNoUrl 
         Caption         =   "Remove no URL"
      End
      Begin VB.Menu mnuDelAllFiles 
         Caption         =   "Delete All Files"
      End
      Begin VB.Menu mnuSelectLike 
         Caption         =   "Selete Like"
      End
      Begin VB.Menu mnuSelNone 
         Caption         =   "Select None"
      End
   End
End
Attribute VB_Name = "Form3"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim urls As New Collection
Dim fso As New CFileSystem2

Private Sub cmdLoad_Click()
    
    'ID,Status,Size,Url
     
     Dim li As ListItem
     Dim e As CEntry
     
     Set urls = New Collection
     
     If Len(txtUrl) = 0 Then
        MsgBox "Must set server script first"
        Exit Sub
     End If
    
     If Len(txtPass) = 0 Then
        MsgBox "Must set script password first"
        Exit Sub
     End If
        
     tmp = Split(Text1, ",")
     lv.ListItems.Clear
    
     For Each X In tmp
        If Len(X) > 0 Then
            X = Replace(X, ".sc.txt", Empty)
            Set e = New CEntry
            If e.LoadRaw(X & String(5, vbTab)) Then  'full: 1253    11.15.11 - 4:51am   1xx.2xx.95.116  2274    cc34d9be7ad27b1614ac4daac89343b4
                Set li = lv.ListItems.Add(, , Trim(X))
                Set li.Tag = e
                li.SubItems(3) = e.ExtractedUrl
                If Len(e.ExtractedUrl) > 0 Then
                    If keyExistsInCollection(urls, li.SubItems(3)) Then
                        li.SubItems(1) = "Duplicate"
                    Else
                        urls.Add li.SubItems(3), li.SubItems(3)
                    End If
                End If
                li.SubItems(2) = Len(e.scLog)
                lv.Refresh
            End If
        End If
     Next
     
     Me.Caption = lv.ListItems.Count & " files"
     DoEvents
     lv.Refresh
     Me.Refresh
     
End Sub

Private Sub Command1_Click()
    'ID,Status,Size,Url
     
     Dim li As ListItem
     Dim e As CEntry
     
     Set urls = New Collection
     
     If Len(txtUrl) = 0 Then
        MsgBox "Must set server script first"
        Exit Sub
     End If
    
     If Len(txtPass) = 0 Then
        MsgBox "Must set script password first"
        Exit Sub
     End If
        
'     tmp = Split(Text1, ",")
'     lv.ListItems.Clear
'
'     For Each X In tmp
'        If Len(X) > 0 Then
'            X = Replace(X, ".sc.txt", Empty)
'            Set e = New CEntry
'            If e.LoadRaw(X & String(5, vbTab)) Then  'full: 1253    11.15.11 - 4:51am   1xx.2xx.95.116  2274    cc34d9be7ad27b1614ac4daac89343b4
'                Set li = lv.ListItems.Add(, , Trim(X))
'                Set li.Tag = e
'                li.SubItems(3) = e.ExtractedUrl
'                If keyExistsInCollection(urls, li.SubItems(3)) Then
'                    li.SubItems(1) = "Duplicate"
'                Else
'                    urls.Add li.SubItems(3), li.SubItems(3)
'                End If
'                li.SubItems(2) = Len(e.scLog)
'                lv.Refresh
'            End If
'        End If
'     Next
     
     DoEvents
     lv.Refresh
     Me.Refresh
     
     Dim qs As String
     Dim h As New CHttpPost
     
     h.BaseUrl = txtUrl
     
     For Each li In lv.ListItems
     
        DoEvents
        lv.Refresh
        Me.Refresh
     
        If li.SubItems(1) = "Duplicate" Then GoTo nextone
        
        Set e = li.Tag
        
        qs = "pass=" & txtPass & "&id=" & e.ID & _
              "&comment=" & h.ToHex(e.scLog) & _
              "&url=" & h.ToHex(e.ExtractedUrl) & _
              "&processed=" & chkProcessed.value
        
        responseCode = h.DoPost(qs)
        li.SubItems(1) = h.LastResponse
        li.EnsureVisible
        
nextone:
    Next
        
End Sub

Private Function keyExistsInCollection(c As Collection, k As String) As Boolean
    On Error GoTo hell
    Dim r
    If Len(Trim(k)) = 0 Then Exit Function
    r = c(k)
    keyExistsInCollection = True
    Exit Function
hell:
End Function
Private Sub Form_Load()
     lv.ColumnHeaders(4).Width = lv.Width - lv.ColumnHeaders(4).Left - 500
     For i = 1 To 3
        lv.ColumnHeaders(i).Width = 800
     Next
     txtPass = GetSetting("bulk", "settings", "password", "")
     txtUrl = GetSetting("bulk", "settings", "serverscript", "")
     
     tmp = Clipboard.GetText
     If InStr(tmp, ".sc.txt") > 0 Then Text1 = tmp: cmdLoad_Click
     
End Sub

Private Sub Form_Unload(Cancel As Integer)
    SaveSetting "bulk", "settings", "password", txtPass
    SaveSetting "bulk", "settings", "serverscript", txtUrl
End Sub

Private Sub Label8_Click()
    MsgBox "This is to integrate with my shellcode database. You can read the source to make compatiable with yours", vbInformation
End Sub

Private Sub lv_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Dim e As CEntry
    Set e = Item.Tag
    If e Is Nothing Then Exit Sub
    Form1.Text2 = e.scLog
End Sub

Private Sub lv_KeyDown(KeyCode As Integer, Shift As Integer)
    If KeyCode = vbKeyDelete Then
        Dim li As ListItem
        For i = lv.ListItems.Count To 1 Step -1
            Set li = lv.ListItems(i)
            If li.Selected = True Then
                lv.ListItems.Remove i
            End If
        Next
        Me.Caption = lv.ListItems.Count & " files"
    End If
End Sub

Private Sub mnuDelAllFiles_Click()
    Dim li As ListItem
    Dim base As String
    Dim path  As String
    
    Dim selCount As Long
    Dim selOnly As VbMsgBoxResult
    Dim doIt As Boolean
    
    For Each li In lv.ListItems
        If li.Selected Then selCount = selCount + 1
    Next
    
    If selCount > 0 Then
        selOnly = MsgBox("Delete Selected = YES, UNSelected = NO", vbYesNoCancel)
        If selOnly = vbCancel Then Exit Sub
    End If
    
    base = Form1.Text1 & "\"
    For i = lv.ListItems.Count To 1 Step -1
        Set li = lv.ListItems(i)
        
        doIt = False
        If selOnly = vbYes Then If li.Selected Then doIt = True
        If selOnly = vbNo Then If Not li.Selected Then doIt = True
        
        If doIt Then
            path = base & li.Text & ".sc"
            If fso.FileExists(path) Then
                fso.DeleteFile path
                fso.DeleteFile path & ".txt"
                li.SubItems(1) = "Deleted"
            Else
                li.SubItems(1) = "NotFound"
            End If
        End If
        
    Next
End Sub

Private Sub mnuNoUrl_Click()
    Dim li As ListItem
    For i = lv.ListItems.Count To 1 Step -1
        Set li = lv.ListItems(i)
        If Len(li.SubItems(3)) = 0 Then
            lv.ListItems.Remove i
        End If
    Next
    Me.Caption = lv.ListItems.Count & " files"
End Sub

Private Sub mnuSelectLike_Click()
    Dim li As ListItem
    Dim e As CEntry
    Dim find As String
    
    find = InputBox("Enter text to search for in run log")
    If Len(find) = 0 Then Exit Sub
    
    For Each li In lv.ListItems
        Set e = li.Tag
        If InStr(1, e.scLog, find, vbTextCompare) > 0 Then li.Selected = True
    Next
    lv.SetFocus
    Me.Caption = lv.ListItems.Count & " files"
End Sub

Private Sub mnuSelNone_Click()
    For Each li In lv.ListItems
        li.Selected = False
    Next
End Sub
