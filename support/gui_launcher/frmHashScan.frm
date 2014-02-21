VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form frmHashScan 
   Caption         =   "Hash Scanner"
   ClientHeight    =   4770
   ClientLeft      =   60
   ClientTop       =   630
   ClientWidth     =   6300
   LinkTopic       =   "Form2"
   ScaleHeight     =   4770
   ScaleWidth      =   6300
   StartUpPosition =   2  'CenterScreen
   Begin VB.Frame fraScan 
      BorderStyle     =   0  'None
      Height          =   330
      Left            =   4005
      TabIndex        =   3
      Top             =   0
      Width           =   2265
      Begin VB.CommandButton cmdScan 
         Caption         =   "Scan"
         Height          =   330
         Left            =   1440
         TabIndex        =   6
         Top             =   0
         Width           =   780
      End
      Begin VB.OptionButton Option1 
         Caption         =   "file"
         Height          =   240
         Index           =   1
         Left            =   810
         TabIndex        =   5
         Top             =   45
         Value           =   -1  'True
         Width           =   690
      End
      Begin VB.OptionButton Option1 
         Height          =   240
         Index           =   0
         Left            =   45
         TabIndex        =   4
         Top             =   45
         Width           =   195
      End
      Begin VB.Label Label1 
         Caption         =   "hash"
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
         Height          =   240
         Left            =   315
         TabIndex        =   7
         Top             =   45
         Width           =   510
      End
   End
   Begin MSComctlLib.ListView lv 
      Height          =   4035
      Left            =   60
      TabIndex        =   2
      Top             =   660
      Width           =   6195
      _ExtentX        =   10927
      _ExtentY        =   7117
      View            =   3
      LabelEdit       =   1
      LabelWrap       =   -1  'True
      HideSelection   =   0   'False
      FullRowSelect   =   -1  'True
      GridLines       =   -1  'True
      _Version        =   393217
      ForeColor       =   -2147483640
      BackColor       =   -2147483643
      BorderStyle     =   1
      Appearance      =   1
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Courier New"
         Size            =   12
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      NumItems        =   3
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "offset"
         Object.Width           =   2469
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "hash"
         Object.Width           =   3175
      EndProperty
      BeginProperty ColumnHeader(3) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   2
         Text            =   "name"
         Object.Width           =   2540
      EndProperty
   End
   Begin MSComctlLib.ProgressBar pb 
      Height          =   255
      Left            =   0
      TabIndex        =   1
      Top             =   360
      Width           =   6255
      _ExtentX        =   11033
      _ExtentY        =   450
      _Version        =   393216
      Appearance      =   1
   End
   Begin VB.TextBox Text1 
      Height          =   375
      Left            =   0
      OLEDropMode     =   1  'Manual
      TabIndex        =   0
      Top             =   0
      Width           =   3930
   End
   Begin VB.Menu mnuPopup 
      Caption         =   "mnuPopup"
      Begin VB.Menu mnUCopyAll 
         Caption         =   "Copy All"
      End
      Begin VB.Menu mnuGenerateIDC 
         Caption         =   "Generate IDC Script"
      End
   End
End
Attribute VB_Name = "frmHashScan"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
 Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" _
    (ByRef Destination As Long, ByRef Source As Byte, ByVal Length As Long)

Private Declare Function URLDownloadToFile Lib "urlmon" Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long


Dim loaded As Boolean
Dim c As New Collection

Private Function DownloadFile(url As String, saveAs As String) As Boolean
    If URLDownloadToFile(0, url, saveAs, 0, 0) = 0 Then DownloadFile = True
End Function


Private Sub cmdScan_Click()
        
    Dim b() As Byte
    Dim x As Long
    Dim li As ListItem
    Dim tmp As String
    Dim hashName As String
    Dim hashVal As String
    Dim ary() As String
    
    On Error Resume Next
    
    lv.ListItems.Clear
    Me.Caption = "Scanning.."
    
    If Option1(0).Value Then 'its a hash scan
        ary() = Split(Text1, ",")
        mnuGenerateIDC.Enabled = False
        For Each v In ary
            tmp = UCase(Trim(v))
            If Len(tmp) > 0 Then
            
                If VBA.Left(tmp, 2) = "0X" Then tmp = Replace(tmp, "0X", "0x")
                If VBA.Left(tmp, 2) <> "0x" Then tmp = "0x" & tmp
                If Right(tmp, 1) = "H" Then tmp = VBA.Left(tmp, Len(tmp) - 1)
                
                If Len(tmp) <> 10 Then
                    MsgBox "Expecting a 8 character hex code as hash. Error on input '" & v & "'", vbInformation
                    Exit Sub
                End If
                
                hashName = c(tmp) 'see if it exists as a key in our loaded collection
                 
                If Len(hashName) > 0 Then
                     Set li = lv.ListItems.Add(, , "")
                     li.SubItems(1) = tmp
                     li.SubItems(2) = hashName
                     Me.Caption = "Found!"
                Else
                    Me.Caption = "No results for hash: " & tmp
                End If
                    
            End If
        Next
        
        Exit Sub
    End If
    
    
    If Not FileExists(Text1) Then
        MsgBox "Input file not found"
        Exit Sub
    End If
    
    If Not loaded Then
        MsgBox "Not loaded yet"
        Exit Sub
    End If
    
    
    mnuGenerateIDC.Enabled = True
    b() = ReadFile(Text1)
    
    pb.Value = 0
    pb.max = 101
    
    For i = 0 To UBound(b) - 3
        CopyMemory x, b(i), 4
        
        hashVal = Empty
        hashName = Empty
        hashVal = "0x" & Right("00000000" & Hex(x), 8)
        hashName = c(hashVal) 'hex() can barf on some longs...fuckers
         
        If Len(hashName) > 0 Then
             Set li = lv.ListItems.Add(, , Hex(i))
             li.SubItems(1) = hashVal
             li.SubItems(2) = hashName
        End If
        
        setpcent CLng(i), UBound(b)
    Next
    
    Me.Caption = "Complete: " & lv.ListItems.Count & " detections..."
    pb.Value = 0
    
End Sub
 
Sub setpcent(cur As Long, max As Long)
    
    On Error Resume Next
    p = (max / cur) * 100
    pb.Value = p
    pb.Refresh
    Me.Refresh
    DoEvents
    
End Sub

Private Sub Form_Resize()
    On Error Resume Next
    lv.Width = Me.Width - lv.Left - 150
    lv.Height = Me.Height - lv.Top - 500
    pb.Width = lv.Width
    lv.ColumnHeaders(3).Width = lv.Width - lv.ColumnHeaders(3).Left - 100
    fraScan.Left = Me.Width - fraScan.Width - 100
    Text1.Width = fraScan.Left - 100
End Sub

Private Sub Label1_Click()
    MsgBox "Enter a 8 character hex hash code to lookup." & vbCrLf & vbCrLf & "You can enter multiple hashs seperated by commas", vbInformation
End Sub

Private Sub lv_MouseUp(Button As Integer, Shift As Integer, x As Single, y As Single)
    PopupMenu mnuPopup
End Sub

Private Sub mnUCopyAll_Click()
    Dim tmp As String
    Dim li As ListItem
    For Each li In lv.ListItems
        tmp = tmp & li.Text & ", " & li.SubItems(1) & ", " & li.SubItems(2) & vbCrLf
    Next
    Clipboard.Clear
    Clipboard.SetText tmp
    
    MsgBox Len(tmp) & " bytes copied to clipboard!", vbInformation
    
End Sub

Private Sub mnuGenerateIDC_Click()
    Dim li As ListItem
    Dim r As String
    
    On Error Resume Next
     
    For Each li In lv.ListItems
        r = r & "MakeComm(0x" & li.Text & ", """ & li.SubItems(2) & """);" & vbCrLf
    Next
    
    Clipboard.Clear
    Clipboard.SetText r
    MsgBox Len(r) & " bytes copied to clipboard" & vbCrLf & vbCrLf & "Note: RAW file offsets were used. You may have to manually adjust.", vbInformation
    
End Sub

Private Sub Text1_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, x As Single, y As Single)
    Text1 = Data.Files(1)
End Sub

Function ReadFile(filename) As Byte()
  f = FreeFile
  Dim temp() As Byte
  ReDim temp(FileLen(filename))
  Open filename For Binary As #f        ' Open file.(can be text or image)
  Get f, , temp()
  Close #f
  ReadFile = temp
End Function

Function FileExists(path) As Boolean
  If Dir(path, vbHidden Or vbNormal Or vbReadOnly Or vbSystem) <> "" Then FileExists = True _
  Else FileExists = False
End Function

Private Sub Form_Load()
    
    mnuPopup.Visible = False
    cmdScan.Enabled = False
    
    Dim cn As New Connection
    Dim rs As Recordset
    Dim db As String
    Dim url As String
    Dim msg As String
        
    msg = "The hash database is not installed by default because of its size." & _
           vbCrLf & vbCrLf & "Do you want to download the latest version?"
        
    url = "https://github.com/dzzie/VS_LIBEMU/raw/master/hashs.7z"

    db = App.path & IIf(isIDE(), "\..\..\", "\") & "\hashs.mdb"
    
    If Not FileExists(db) Then
    
        db = Replace(db, ".mdb", ".7z")
        If MsgBox(msg, vbYesNo) = vbNo Then Exit Sub
        
        If Not DownloadFile(url, db) Then
            MsgBox "Download failed..", vbInformation
            Exit Sub
        End If
        
        If fso.FileExists(db) Then
            MsgBox "The file was downloaded successfully as hashs.7z in the applications home directory." & vbCrLf & vbCrLf & "You will still have to manually unzip it", vbInformation
            Exit Sub
        End If
        
        MsgBox "Could not find downloaded file?", vbInformation
        Exit Sub
        
    End If
    
    cmdScan.Enabled = True
    cn.ConnectionString = "Provider=MSDASQL;Driver={Microsoft Access Driver (*.mdb)};DBQ=" & db & ";"
    cn.Open
    
    Set rs = cn.Execute("Select * from tblHashs")
    
    Me.Caption = "Loading hashs..."
    Me.Refresh
    
    On Error Resume Next
    
    While Not rs.EOF
        'Err.Clear
        c.Add CStr(rs!hashName), CStr(rs!hashValue)
'        For i = 0 To 5
'            If Err.Number = 0 Then Exit For
'            Err.Clear
'            c.Add CStr(rs!hashName), CStr(rs!hashValue) & "_" & i 'this is how we index conflicts..
'        Next
        rs.MoveNext
    Wend
    
    Me.Caption = c.Count & " Hashs successfully loaded..."
    Me.Refresh
    loaded = True
    cn.Close
    
    cmdScan.Enabled = True
    
End Sub
