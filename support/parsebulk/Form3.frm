VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "MSCOMCTL.OCX"
Begin VB.Form Form3 
   Caption         =   "Form3"
   ClientHeight    =   4890
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10890
   LinkTopic       =   "Form3"
   ScaleHeight     =   4890
   ScaleWidth      =   10890
   StartUpPosition =   3  'Windows Default
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
      Left            =   9120
      TabIndex        =   4
      Top             =   0
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
      LabelWrap       =   -1  'True
      HideSelection   =   -1  'True
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
      Caption         =   "Upload Reports"
      Height          =   375
      Left            =   9240
      TabIndex        =   2
      Top             =   360
      Width           =   1575
   End
   Begin VB.TextBox Text1 
      Height          =   375
      Left            =   960
      TabIndex        =   1
      Top             =   360
      Width           =   8055
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
End
Attribute VB_Name = "Form3"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim urls As New Collection

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
                If keyExistsInCollection(urls, li.SubItems(3)) Then
                    li.SubItems(1) = "Duplicate"
                Else
                    urls.Add li.SubItems(3), li.SubItems(3)
                End If
                li.SubItems(2) = Len(e.scLog)
                lv.Refresh
            End If
        End If
     Next
     
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
End Sub

Private Sub Form_Unload(Cancel As Integer)
    SaveSetting "bulk", "settings", "password", txtPass
    SaveSetting "bulk", "settings", "serverscript", txtUrl
End Sub

Private Sub Label8_Click()
    MsgBox "This is to integrate with my shellcode database. You can read the source to make compatiable with yours", vbInformation
End Sub
