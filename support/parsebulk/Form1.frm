VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form1 
   Caption         =   "Bulk Analyzer"
   ClientHeight    =   8625
   ClientLeft      =   165
   ClientTop       =   735
   ClientWidth     =   15330
   LinkTopic       =   "Form1"
   ScaleHeight     =   8625
   ScaleWidth      =   15330
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton Command6 
      Caption         =   "Strip"
      Height          =   255
      Left            =   8040
      TabIndex        =   28
      Top             =   7920
      Width           =   1095
   End
   Begin VB.CommandButton Command5 
      Caption         =   "Copy"
      Height          =   255
      Left            =   9240
      TabIndex        =   27
      Top             =   7920
      Width           =   1095
   End
   Begin VB.CommandButton Command4 
      Caption         =   "Clear"
      Height          =   255
      Left            =   10440
      TabIndex        =   26
      Top             =   7920
      Width           =   1095
   End
   Begin VB.CommandButton Command3 
      Caption         =   "Bulk Delete"
      Height          =   255
      Left            =   11760
      TabIndex        =   25
      Top             =   7920
      Width           =   975
   End
   Begin VB.TextBox Text3 
      Height          =   285
      Left            =   3360
      TabIndex        =   24
      Top             =   7560
      Width           =   11175
   End
   Begin VB.TextBox Text2 
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   9.75
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   6495
      Left            =   3360
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   6
      Top             =   960
      Width           =   11175
   End
   Begin MSComctlLib.ListView lvFiles 
      Height          =   2895
      Left            =   0
      TabIndex        =   5
      Top             =   720
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   5106
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.CommandButton Command2 
      Caption         =   "Run scdbg"
      Height          =   375
      Left            =   7680
      TabIndex        =   3
      Top             =   0
      Width           =   1455
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Parse Results"
      Height          =   375
      Left            =   9240
      TabIndex        =   2
      Top             =   0
      Width           =   1215
   End
   Begin VB.TextBox Text1 
      Height          =   375
      Left            =   720
      OLEDropMode     =   1  'Manual
      TabIndex        =   1
      Text            =   "D:\_libemu\VS_LIBEMU\unprocessed"
      Top             =   0
      Width           =   6855
   End
   Begin MSComctlLib.ListView lvOpcode 
      Height          =   1095
      Left            =   1680
      TabIndex        =   10
      Top             =   960
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   1931
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvNoMem 
      Height          =   1215
      Left            =   1680
      TabIndex        =   12
      Top             =   2400
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvNoAccess 
      Height          =   1215
      Left            =   1680
      TabIndex        =   14
      Top             =   3960
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvDownload 
      Height          =   1215
      Left            =   1680
      TabIndex        =   17
      Top             =   5520
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvOverStep 
      Height          =   1215
      Left            =   1680
      TabIndex        =   18
      Top             =   7080
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvUnhooked 
      Height          =   1215
      Left            =   0
      TabIndex        =   21
      Top             =   5520
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView LvNot 
      Height          =   1215
      Left            =   0
      TabIndex        =   22
      Top             =   7080
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ListView lvFileScanner 
      Height          =   1215
      Left            =   0
      TabIndex        =   31
      Top             =   3960
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   2143
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.Label Label5 
      Caption         =   "File Handle Scanner"
      Height          =   255
      Index           =   7
      Left            =   0
      TabIndex        =   32
      Top             =   3720
      Width           =   1455
   End
   Begin VB.Label Label8 
      Caption         =   "Report Uploader"
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
      Left            =   5040
      TabIndex        =   30
      Top             =   480
      Width           =   1335
   End
   Begin VB.Label Label7 
      Caption         =   "Manifest Viewer"
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
      Left            =   3600
      TabIndex        =   29
      Top             =   480
      Width           =   1335
   End
   Begin VB.Label Label5 
      Caption         =   "Not Detected"
      Height          =   255
      Index           =   6
      Left            =   0
      TabIndex        =   23
      Top             =   6840
      Width           =   975
   End
   Begin VB.Label Label5 
      Caption         =   "UnHooked"
      Height          =   255
      Index           =   5
      Left            =   0
      TabIndex        =   20
      Top             =   5280
      Width           =   975
   End
   Begin VB.Label Label5 
      Caption         =   "Overstep"
      Height          =   255
      Index           =   4
      Left            =   1680
      TabIndex        =   19
      Top             =   6840
      Width           =   975
   End
   Begin VB.Label Label5 
      Caption         =   "Download"
      Height          =   255
      Index           =   3
      Left            =   1680
      TabIndex        =   16
      Top             =   5280
      Width           =   975
   End
   Begin VB.Label Label6 
      Caption         =   "Urls"
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
      Left            =   3000
      TabIndex        =   15
      Top             =   480
      Width           =   375
   End
   Begin VB.Label Label5 
      Caption         =   "NoAcess"
      Height          =   255
      Index           =   2
      Left            =   1680
      TabIndex        =   13
      Top             =   3720
      Width           =   975
   End
   Begin VB.Label Label5 
      Caption         =   "NoMem"
      Height          =   255
      Index           =   1
      Left            =   1680
      TabIndex        =   11
      Top             =   2160
      Width           =   975
   End
   Begin VB.Label Label5 
      Caption         =   "Opcode"
      Height          =   255
      Index           =   0
      Left            =   1680
      TabIndex        =   9
      Top             =   720
      Width           =   975
   End
   Begin VB.Label Label4 
      Caption         =   "Not Detected"
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
      Left            =   1680
      TabIndex        =   8
      Top             =   480
      Width           =   1215
   End
   Begin VB.Label Label3 
      Caption         =   "Log"
      Height          =   255
      Left            =   3600
      TabIndex        =   7
      Top             =   720
      Width           =   735
   End
   Begin VB.Label Label2 
      Caption         =   "Files"
      Height          =   375
      Left            =   120
      TabIndex        =   4
      Top             =   480
      Width           =   1455
   End
   Begin VB.Label Label1 
      Caption         =   "Folder"
      Height          =   255
      Left            =   120
      TabIndex        =   0
      Top             =   120
      Width           =   735
   End
   Begin VB.Menu mnuPopup 
      Caption         =   "mnuPopup"
      Begin VB.Menu mnuMoveTo 
         Caption         =   "Move to folder"
      End
      Begin VB.Menu mnuDeleteFiles 
         Caption         =   "Delete Files"
      End
      Begin VB.Menu mnuGenList 
         Caption         =   "Generate List"
      End
      Begin VB.Menu mnuViewHex 
         Caption         =   "View HexDump"
      End
      Begin VB.Menu mnuRunScdbg 
         Caption         =   "Run in Scdbg"
      End
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim fso As New CFileSystem2
Dim notDetected As String
Dim urls As String
Dim LiveLv As ListView

Private Sub Command1_Click()
    On Error Resume Next
    Dim ff() As String
    Dim f, li As ListItem, lv As ListView
    
    If Not fso.FolderExists(Text1) Then
        MsgBox "Folder not found"
        Exit Sub
    End If
    
    ff() = fso.GetFolderFiles(Text1, "*.txt")
     
    lvFiles.ListItems.Clear
    lvOpcode.ListItems.Clear
    lvNoMem.ListItems.Clear
    lvNoAccess.ListItems.Clear
    lvDownload.ListItems.Clear
    lvOverStep.ListItems.Clear
    lvUnhooked.ListItems.Clear
    LvNot.ListItems.Clear
    notDetected = Empty
    urls = Empty
    
    For Each f In ff
        d = fso.ReadFile(f)
        
        If InStr(d, "No shellcode detected") > 0 Then
            Set lv = LvNot
            notDetected = notDetected & fso.FileNameFromPath(CStr(f)) & ","
        ElseIf InStr(d, "not supported") > 0 Then
            Set lv = lvOpcode
        ElseIf InStr(d, "emu_parse no memory found") > 0 Then
            Set lv = lvNoMem
        ElseIf InStr(d, "error accessing") > 0 Then
            Set lv = lvNoAccess
        ElseIf InStr(d, "open file handle scanning occuring") > 0 Then
             Set lv = lvFileScanner
        ElseIf InStr(d, "Stepcount 2000001") > 0 Then
            Set lv = lvOverStep
        ElseIf InStr(d, "unhooked call to") > 0 Then
             Set lv = lvUnhooked
        Else
            Set lv = lvFiles
        End If
        
        If InStr(d, "URLDownload") > 0 Then
            
            Set lv = lvDownload
            
            a = InStr(d, "URLDownload")
            a = InStr(a, d, "(") + 1
            b = InStr(a, d, ")")
            X = Mid(d, a, b - a)
            
            urls = urls & fso.FileNameFromPath(CStr(f)) & " " & _
                        Split(X, ",")(0) & vbCrLf
                        'Join(Split(x, ","), vbCrLf & vbTab) & _
                        vbCrLf
                    
        End If
        
        If Not lv Is Nothing Then
            Set li = lv.ListItems.Add()
            If lv Is LvNot Then
                li.Tag = Hexdump(fso.ReadFile(Mid(f, 1, Len(f) - 4)))
            Else
                li.Tag = d
            End If
            
            li.Text = fso.FileNameFromPath(CStr(f))
        End If
        
    Next
    
    lvOpcode.ColumnHeaders(1).Text = lvOpcode.ListItems.count
    lvNoMem.ColumnHeaders(1).Text = lvNoMem.ListItems.count
    lvFiles.ColumnHeaders(1).Text = lvFiles.ListItems.count
    lvNoAccess.ColumnHeaders(1).Text = lvNoAccess.ListItems.count
    lvDownload.ColumnHeaders(1).Text = lvDownload.ListItems.count
    lvOverStep.ColumnHeaders(1).Text = lvOverStep.ListItems.count
    lvUnhooked.ColumnHeaders(1).Text = lvUnhooked.ListItems.count
    lvFileScanner.ColumnHeaders(1).Text = lvFileScanner.ListItems.count
    LvNot.ColumnHeaders(1).Text = LvNot.ListItems.count
    Label2.Caption = UBound(ff) & " Files total"
    
End Sub

Private Sub Command2_Click()
    MsgBox "Not implemented yet run scdbg -dir [folder]", vbInformation
End Sub

Private Sub Command3_Click()
    If MsgBox("Delete all these files?!", vbInformation + vbYesNo) = vbNo Then
        Exit Sub
    End If
    
    On Error Resume Next
    
    tmp = Split(Text3, ",")
    For Each X In tmp
        Kill Text1 & "\" & X
        Kill Text1 & "\" & Mid(X, 1, Len(X) - 4)
    Next
    
    MsgBox "Complete! errors?=  " & Err.Description
    
End Sub

Private Sub Command4_Click()
    Text3 = Empty
End Sub

Private Sub Command5_Click()
    Clipboard.Clear
    Clipboard.SetText Text3
    MsgBox "Copied " & Len(Text3) & " bytes to clipboard"
End Sub

Private Sub Command6_Click()
    X = InputBox("Enter text to strip from file list", , ".sc.txt")
    If Len(X) = 0 Then Exit Sub
    Text3 = Replace(Text3, X, Empty)
End Sub

Private Sub Form_Load()
    On Error GoTo isIde
        Debug.Print 1 / 0
        Text1 = "Drag and drop folder here that contains -dir processed samples/reports"
        mnuPopup.Visible = False
    Exit Sub
isIde:
    
End Sub

Private Sub Label4_Click()
    Text2 = notDetected
End Sub

Private Sub Label4_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
    Set LiveLv = LvNot     'hidden
End Sub

Private Sub Label6_Click()
    Text2 = urls
End Sub

Private Sub Label7_Click()
    m = Text1 & "\manifest.txt"
    If Not fso.FileExists(CStr(m)) Then
        MsgBox "This feature is for a specific file format from an internal database, see source for format. used for data visualization and sorting", vbInformation
        Exit Sub
    End If
    Call Form2.LoadManifest(m)
End Sub

Private Sub Label8_Click()
    Form3.Show
End Sub

'*************************************************************************
Private Sub LvNot_DblClick()
    On Error Resume Next
    Text3 = Text3 & LvNot.SelectedItem.Text & ","
End Sub
Private Sub Lvopcode_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvOpcode.SelectedItem.Text & ","
End Sub
Private Sub Lvnoaccess_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvNoAccess.SelectedItem.Text & ","
End Sub
Private Sub Lvnomem_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvNoMem.SelectedItem.Text & ","
End Sub
Private Sub Lvdownload_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvDownload.SelectedItem.Text & ","
End Sub
Private Sub Lvfiles_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvFiles.SelectedItem.Text & ","
End Sub
Private Sub Lvoverstep_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvOverStep.SelectedItem.Text & ","
End Sub
Private Sub Lvunhooked_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvUnhooked.SelectedItem.Text & ","
End Sub
Private Sub lvFileScanner_DblClick()
    On Error Resume Next
    Text3 = Text3 & lvFileScanner.SelectedItem.Text & ","
End Sub

'*************************************************************************

Private Sub lvOpcode_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvnoaccess_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvNoMem_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvFiles_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvOverStep_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvUnhooked_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvDownload_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvnot_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
Private Sub lvFileScanner_MouseUp(Button As Integer, Shift As Integer, X As Single, Y As Single)
    If Button = 2 Then PopupMenu mnuPopup
End Sub
'*************************************************************************

Private Sub lvOpcode_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvOpcode
End Sub

Private Sub lvNoAccess_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvNoAccess
End Sub
Private Sub lvoverstep_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvOverStep
End Sub

Private Sub lvunhooked_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvUnhooked
End Sub
Private Sub lvnomem_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvNoMem
End Sub
Private Sub lvnot_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = LvNot
End Sub
Private Sub lvDownload_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvDownload
End Sub
Private Sub lvFiles_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvFiles
End Sub
Private Sub lvFileScanner_ItemClick(ByVal Item As MSComctlLib.ListItem)
    On Error Resume Next
    Text2 = Item.Tag
    Set LiveLv = lvFileScanner
End Sub
'*************************************************************************

Private Sub mnuDeleteFiles_Click()
    On Error GoTo hell
    
    If LiveLv Is Nothing Then
        MsgBox "No list selected"
        Exit Sub
    End If
    
    If MsgBox("Are you sure you want to delete these files?", vbYesNo) = vbNo Then
        Exit Sub
    End If
    
    Dim li As ListItem
    For Each li In LiveLv.ListItems
        f = Text1 & "\" & li.Text
        Kill f
        Kill Mid(f, 1, Len(f) - 4)
    Next
        
    Exit Sub
hell:
    MsgBox Err.Description & vbCrLf & "Last file: " & f, vbExclamation
    
End Sub

Private Sub mnuGenList_Click()
    On Error GoTo hell
    
    If LiveLv Is Nothing Then
        MsgBox "No list selected"
        Exit Sub
    End If
    
    Dim li As ListItem
    Dim tmp
    For Each li In LiveLv.ListItems
        tmp = tmp & li.Text & ","
    Next
    Text3 = tmp
    
    Exit Sub
hell:
    MsgBox Err.Description & vbCrLf & "Last file: " & f, vbExclamation
End Sub

Private Sub mnuMoveTo_Click()
    On Error GoTo hell
    Dim ff As String
    
    If LiveLv Is Nothing Then
        MsgBox "No list selected"
        Exit Sub
    End If
    
    ff = Text1 & "\" & LiveLv.Name
    If Not fso.FolderExists(CStr(ff)) Then
        If Not fso.CreateFolder(CStr(ff)) Then
            MsgBox "Failed to create " & ff
            Exit Sub
        End If
    End If
        
    Dim li As ListItem
    For Each li In LiveLv.ListItems
        f = Text1 & "\" & li.Text
        fso.Move CStr(f), ff '.txt log file
        fso.Move Mid(f, 1, Len(f) - 4), ff  'parent shellcode file (name - .txt)
    Next
        
    Exit Sub
hell:
    MsgBox Err.Description & vbCrLf & "Last file: " & f, vbExclamation
    
End Sub

Private Sub mnuRunScdbg_Click()

    If LiveLv Is Nothing Then
        MsgBox "No list selected"
        Exit Sub
    End If
    
    f = Text1 & "\" & LiveLv.SelectedItem.Text
    f = Mid(f, 1, Len(f) - 4)
    If Not fso.FileExists(CStr(f)) Then
        MsgBox "File not found: " & f
        Exit Sub
    End If
    
    frmScTest.InitInterface CStr(f)
    
End Sub

Private Sub mnuViewHex_Click()
    If LiveLv Is Nothing Then
        MsgBox "No list selected"
        Exit Sub
    End If
    
    f = Text1 & "\" & LiveLv.SelectedItem.Text
    f = Mid(f, 1, Len(f) - 4)
    If Not fso.FileExists(CStr(f)) Then
        MsgBox "File not found: " & f
        Exit Sub
    End If
    
    Text2 = Hexdump(fso.ReadFile(f))
    
End Sub

Private Sub Text1_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    On Error Resume Next
    Text1 = Data.files(1)
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

Private Sub push(ary, value)
    On Error GoTo init
    X = UBound(ary)
    ReDim Preserve ary(UBound(ary) + 1)
    ary(UBound(ary)) = value
    Exit Sub
init: ReDim ary(0): ary(0) = value
End Sub


