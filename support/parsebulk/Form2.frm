VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Object = "{3B7C8863-D78F-101B-B9B5-04021C009402}#1.2#0"; "RICHTX32.OCX"
Begin VB.Form Form2 
   Caption         =   "Form2"
   ClientHeight    =   7170
   ClientLeft      =   165
   ClientTop       =   735
   ClientWidth     =   14595
   LinkTopic       =   "Form2"
   ScaleHeight     =   7170
   ScaleWidth      =   14595
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton Command3 
      Caption         =   "Bulk Delete"
      Height          =   255
      Left            =   13560
      TabIndex        =   6
      Top             =   6840
      Width           =   975
   End
   Begin RichTextLib.RichTextBox Text3 
      Height          =   3255
      Left            =   4200
      TabIndex        =   5
      Top             =   3480
      Width           =   10335
      _ExtentX        =   18230
      _ExtentY        =   5741
      _Version        =   393217
      ScrollBars      =   2
      TextRTF         =   $"Form2.frx":0000
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Courier New"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
   End
   Begin VB.TextBox Text4 
      Height          =   285
      Left            =   4920
      TabIndex        =   3
      Text            =   "Text4"
      Top             =   0
      Width           =   1335
   End
   Begin VB.TextBox Text2 
      Height          =   285
      Left            =   4200
      TabIndex        =   2
      Text            =   "Text2"
      Top             =   6840
      Width           =   9255
   End
   Begin VB.TextBox Text1 
      Height          =   3015
      Left            =   4200
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   1
      Top             =   360
      Width           =   10215
   End
   Begin MSComctlLib.TreeView tv 
      Height          =   7095
      Left            =   0
      TabIndex        =   0
      Top             =   0
      Width           =   4095
      _ExtentX        =   7223
      _ExtentY        =   12515
      _Version        =   393217
      LabelEdit       =   1
      LineStyle       =   1
      Style           =   7
      Appearance      =   1
   End
   Begin VB.Label Label1 
      Caption         =   "ID"
      Height          =   255
      Left            =   4320
      TabIndex        =   4
      Top             =   0
      Width           =   495
   End
   Begin VB.Menu mnuPopup1 
      Caption         =   "mnuPopup1"
      Visible         =   0   'False
      Begin VB.Menu mnuWhois 
         Caption         =   "Whois"
      End
      Begin VB.Menu mnuAdd2List 
         Caption         =   "Add 2 List"
      End
      Begin VB.Menu mnuDeleteAll 
         Caption         =   "Delete All"
      End
   End
   Begin VB.Menu mnuTools 
      Caption         =   "Tools"
      Begin VB.Menu mnuExpandAll 
         Caption         =   "Expand All"
      End
      Begin VB.Menu mnuColapseAll 
         Caption         =   "Collapse All"
      End
      Begin VB.Menu mnuCopyAll 
         Caption         =   "Copy All"
      End
      Begin VB.Menu mnuCopyIp 
         Caption         =   "Copy Ips Only"
      End
   End
End
Attribute VB_Name = "Form2"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim fso As New CFileSystem2
Dim uniqueIPs As New Collection
Dim entries As New Collection 'of CEntry
Dim selNode As Node

Public Function LoadManifest(path)
    'manifest file format
    '1253    11.15.11 - 4:51am   1xx.2xx.95.116  2274    cc34d9be7ad27b1614ac4daac89343b4
    '1252    11.15.11 - 4:46am   1xx.2xx.95.116  2278    5349633f9d4a9c6afb58d31b84bc9ee0
    
    Dim e As CEntry
    Dim n As Node
    Dim e2 As CEntry
    Dim n2 As Node
    
    Me.Show
    d = fso.ReadFile(path)
    tmp = Split(d, vbCrLf)
    For Each lineentry In tmp
        If Len(lineentry) > 0 Then
            Set e = New CEntry
            If e.LoadRaw(lineentry) Then
                addUnique e
                entries.Add e
                
            End If
        End If
    Next
    
    Debug.Print "Unique: " & uniqueIPs.Count & " Total: " & entries.Count
    
    For Each e In uniqueIPs
        Set n = tv.Nodes.Add(, , , e.ip)
        For Each e2 In entries
            If e2.ip = e.ip Then
                Set n2 = tv.Nodes.Add(n, tvwChild, , e2.SDate & " - " & e2.Size)
                Set n2.Tag = e2
                Set e2.tvNode = n2
                If e2.Missing Then
                    n2.ForeColor = vbRed
                End If
            End If
        Next
        n.Text = n.Text & " (" & n.Children & ")"
    Next
    
        
    Me.Caption = "Total: " & entries.Count
        
    
    
End Function

Private Function addUnique(e As CEntry)
    On Error Resume Next
    uniqueIPs.Add e, "ip:" & e.ip
    If Err.Number = 0 Then Debug.Print "Unique ip added: " & e.ip
End Function

Private Sub Command3_Click()
    If MsgBox("Delete all these files?!", vbInformation + vbYesNo) = vbNo Then
        Exit Sub
    End If
    
    On Error Resume Next
    Dim e As CEntry
    Dim p As Node
    
    tmp = Split(Text2, ",")
    For Each X In tmp
        For Each e In entries
            If e.ID = X Then
                Kill e.LogPath
                Kill e.SCPath
                Set p = e.tvNode.Parent
                tv.Nodes.Remove e.tvNode.Index
                If p.Children = 0 Then tv.Nodes.Remove p.Index
            End If
        Next
    Next
    
    MsgBox "Complete!"
    Me.Caption = "Total: " & (tv.Nodes.Count - uniqueIPs.Count)
    
End Sub

Private Sub mnuAdd2List_Click()
    On Error Resume Next
    Dim e As CEntry
    If selNode Is Nothing Then Exit Sub
    If selNode.Children = 0 Then Exit Sub 'only valid for parent ips listings
    For Each n In tv.Nodes
        If Not n.Parent Is Nothing Then
            If n.Parent = selNode Then
                Set e = n.Tag
                tmp = tmp & e.ID & ","
            End If
        End If
    Next
    Text2 = Text2 & tmp
End Sub

Private Sub mnuColapseAll_Click()
    Dim n As Node
    For Each n In tv.Nodes
        n.Expanded = False
    Next
End Sub

Private Sub mnuCopyAll_Click()
    Dim n As Node
    Dim tmp
    For Each n In tv.Nodes
        If n.Children = 0 Then tmp = tmp & vbTab
        tmp = tmp & n.Text & vbCrLf
    Next
    Clipboard.Clear
    Clipboard.SetText tmp
    Text1 = tmp
    
End Sub

Private Sub mnuCopyIp_Click()
    Dim n As Node
    Dim tmp
    For Each n In tv.Nodes
        If n.Children > 0 Then
            a = InStr(n.Text, "(") - 1
            tmp = tmp & Mid(n.Text, 1, a) & vbCrLf
        End If
    Next
    Clipboard.Clear
    Clipboard.SetText tmp
    Text1 = tmp
End Sub

Private Sub mnuDeleteAll_Click()
    On Error Resume Next
    Dim e As CEntry
    Dim n As Node
    
    If selNode Is Nothing Then Exit Sub
    If selNode.Children = 0 Then Exit Sub 'only valid for parent ips listings
    If MsgBox("Sure to delete these files? Did you save the IDs?", vbYesNo) = vbNo Then Exit Sub
    
    For Each n In tv.Nodes
        If Not n.Parent Is Nothing Then
            If n.Parent = selNode Then
                Set e = n.Tag
                Kill e.LogPath
                Kill e.SCPath
                n.ForeColor = vbRed
            End If
        End If
    Next
    
    For i = tv.Nodes.Count To 1 Step -1
        Set n = tv.Nodes(i)
        If n.ForeColor = vbRed Then
            tv.Nodes.Remove n.Index
        End If
    Next
    
    tv.Nodes.Remove selNode.Index
    Me.Caption = "Total: " & (tv.Nodes.Count - uniqueIPs.Count)
    
End Sub

Private Sub mnuExpandAll_Click()
    Dim n As Node
    For Each n In tv.Nodes
        n.Expanded = True
    Next
End Sub

Private Sub mnuWhois_Click()
    On Error Resume Next
    If selNode Is Nothing Then Exit Sub
    ip = selNode.Text
    a = InStr(ip, "(")
    If a > 0 Then ip = Trim(Mid(ip, 1, a - 1))
    Shell "cmd /k whois " & ip, vbNormalFocus
End Sub

Private Sub tv_DblClick()
    Dim e As CEntry
    If selNode Is Nothing Then Exit Sub
    If selNode.Children = 0 Then
        Set e = selNode.Tag
        Text2 = Text2 & e.ID & ","
    End If
End Sub

Private Sub tv_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If selNode Is Nothing Then Exit Sub
    If Button = 2 Then
        If selNode.Children > 0 Then
            PopupMenu mnuPopup1
        End If
    End If
End Sub

Private Sub tv_NodeClick(ByVal Node As MSComctlLib.Node)
    Dim n As Node
    Dim e As CEntry
    On Error Resume Next
    
    If Node.Children > 0 Then 'its a parent node listing ip address and count
        'For Each n In tv.Nodes
        '    If Not n.Parent Is Nothing Then
        '        If n.Parent = Node Then
        '            Set e = n.Tag
        '            tmp = tmp & e.ID & vbTab & e.SDate & vbTab & e.Size & vbCrLf
        '        End If
        '    End If
        'Next
        'Text1 = tmp
        Node.Expanded = True
        
    Else 'its a specific entry
        
        Set e = Node.Tag
        Text1 = e.scLog
        Text3 = Form1.Hexdump(e.SC)
        Text4 = e.ID
    End If
    Set selNode = Node
End Sub
