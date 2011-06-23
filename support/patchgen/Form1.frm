VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form1 
   Caption         =   "scdbg Patch Viewer/Generator"
   ClientHeight    =   5460
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   10995
   LinkTopic       =   "Form1"
   ScaleHeight     =   5460
   ScaleWidth      =   10995
   StartUpPosition =   3  'Windows Default
   Begin VB.TextBox txtComment 
      Height          =   285
      Left            =   4230
      MaxLength       =   16
      TabIndex        =   36
      Top             =   990
      Width           =   4830
   End
   Begin VB.Frame Frame1 
      Caption         =   " Registers "
      Height          =   4695
      Left            =   9225
      TabIndex        =   17
      Top             =   90
      Width           =   1680
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   7
         Left            =   675
         TabIndex        =   33
         Top             =   2745
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   6
         Left            =   675
         TabIndex        =   31
         Top             =   2385
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   5
         Left            =   675
         TabIndex        =   29
         Top             =   2040
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   4
         Left            =   675
         TabIndex        =   27
         Top             =   1710
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   3
         Left            =   675
         TabIndex        =   25
         Top             =   1350
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   2
         Left            =   675
         TabIndex        =   23
         Top             =   990
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   1
         Left            =   675
         TabIndex        =   21
         Top             =   645
         Width           =   850
      End
      Begin VB.TextBox txtReg 
         Height          =   285
         Index           =   0
         Left            =   660
         TabIndex        =   19
         Top             =   315
         Width           =   850
      End
      Begin VB.Label Label6 
         Caption         =   "EIP is set using /foff  setting Flags not impl"
         Height          =   1275
         Left            =   90
         TabIndex        =   34
         Top             =   3285
         Width           =   1635
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   7
         Left            =   135
         TabIndex        =   32
         Top             =   2790
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   6
         Left            =   135
         TabIndex        =   30
         Top             =   2430
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   5
         Left            =   135
         TabIndex        =   28
         Top             =   2085
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   4
         Left            =   135
         TabIndex        =   26
         Top             =   1755
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   3
         Left            =   135
         TabIndex        =   24
         Top             =   1395
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   2
         Left            =   135
         TabIndex        =   22
         Top             =   1035
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   1
         Left            =   135
         TabIndex        =   20
         Top             =   690
         Width           =   615
      End
      Begin VB.Label lblReg 
         Caption         =   "Label6"
         Height          =   255
         Index           =   0
         Left            =   120
         TabIndex        =   18
         Top             =   360
         Width           =   615
      End
   End
   Begin VB.CommandButton Command2 
      Caption         =   "New"
      Height          =   285
      Left            =   7695
      TabIndex        =   16
      Top             =   585
      Width           =   1410
   End
   Begin VB.CommandButton Command1 
      Caption         =   "..."
      Height          =   285
      Left            =   6795
      TabIndex        =   15
      Top             =   180
      Width           =   780
   End
   Begin MSComctlLib.ListView lv 
      Height          =   3840
      Left            =   90
      TabIndex        =   13
      Top             =   540
      Width           =   2760
      _ExtentX        =   4868
      _ExtentY        =   6773
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
      NumItems        =   2
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "Patches"
         Object.Width           =   2540
      EndProperty
      BeginProperty ColumnHeader(2) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         SubItemIndex    =   1
         Text            =   "Comment"
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.CommandButton cmdRemove 
      Caption         =   "Remove"
      Height          =   375
      Left            =   5265
      TabIndex        =   12
      Top             =   4455
      Width           =   1365
   End
   Begin VB.CommandButton cmdUpdate 
      Caption         =   "Update"
      Enabled         =   0   'False
      Height          =   375
      Left            =   7785
      TabIndex        =   11
      Top             =   4455
      Width           =   1275
   End
   Begin VB.CommandButton cmdSaveAs 
      Caption         =   "Save As"
      Height          =   330
      Left            =   9540
      TabIndex        =   10
      Top             =   4995
      Width           =   1275
   End
   Begin VB.TextBox txtSave 
      Height          =   315
      Left            =   570
      TabIndex        =   9
      Top             =   4995
      Width           =   8805
   End
   Begin VB.CommandButton cmdAdd 
      Caption         =   "Insert"
      Height          =   375
      Left            =   3015
      TabIndex        =   7
      Top             =   4455
      Width           =   1275
   End
   Begin VB.TextBox txtHexData 
      Height          =   2490
      Left            =   3015
      MultiLine       =   -1  'True
      OLEDropMode     =   1  'Manual
      ScrollBars      =   2  'Vertical
      TabIndex        =   6
      Top             =   1845
      Width           =   6045
   End
   Begin VB.TextBox txtMemAddress 
      Height          =   330
      Left            =   4230
      MaxLength       =   8
      TabIndex        =   4
      Top             =   540
      Width           =   1455
   End
   Begin VB.CommandButton cmdLoad 
      Caption         =   "Load Existing"
      Height          =   330
      Left            =   7695
      TabIndex        =   2
      Top             =   180
      Width           =   1410
   End
   Begin VB.TextBox txtLoad 
      Height          =   315
      Left            =   615
      OLEDropMode     =   1  'Manual
      TabIndex        =   1
      Text            =   "Drag and Drop file here"
      Top             =   135
      Width           =   6150
   End
   Begin VB.Label Label7 
      Caption         =   "Comment"
      Height          =   330
      Left            =   3060
      TabIndex        =   35
      Top             =   1035
      Width           =   1050
   End
   Begin VB.Label Label5 
      Caption         =   "load file"
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
      Left            =   8370
      TabIndex        =   14
      Top             =   1575
      Width           =   690
   End
   Begin VB.Label Label4 
      Caption         =   "File"
      Height          =   255
      Left            =   90
      TabIndex        =   8
      Top             =   5040
      Width           =   735
   End
   Begin VB.Label Label3 
      Caption         =   "HexData  (can also drop file to load)"
      Height          =   285
      Left            =   3060
      TabIndex        =   5
      Top             =   1530
      Width           =   4020
   End
   Begin VB.Label Label2 
      Caption         =   "Hex MemAddr"
      Height          =   240
      Left            =   3060
      TabIndex        =   3
      Top             =   585
      Width           =   1590
   End
   Begin VB.Label Label1 
      Caption         =   "File"
      Height          =   255
      Left            =   90
      TabIndex        =   0
      Top             =   180
      Width           =   735
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim patches As New Collection
Dim selLi As ListItem

Private Type patch '16 bytes 1 line in hexeditor
    Memaddress As String * 8
    Datasize As Long
    foffset As Long
    Comment As String * 16
End Type

 
       Private Declare Function GetOpenFileName Lib "comdlg32.dll" Alias _
         "GetOpenFileNameA" (pOpenfilename As OPENFILENAME) As Long

       Private Type OPENFILENAME
         lStructSize As Long
         hwndOwner As Long
         hInstance As Long
         lpstrFilter As String
         lpstrCustomFilter As String
         nMaxCustFilter As Long
         nFilterIndex As Long
         lpstrFile As String
         nMaxFile As Long
         lpstrFileTitle As String
         nMaxFileTitle As Long
         lpstrInitialDir As String
         lpstrTitle As String
         flags As Long
         nFileOffset As Integer
         nFileExtension As Integer
         lpstrDefExt As String
         lCustData As Long
         lpfnHook As Long
         lpTemplateName As String
       End Type

Function OpenFileDialog()
         Dim OpenFile As OPENFILENAME
         Dim lReturn As Long
         Dim sFilter As String
         OpenFile.lStructSize = Len(OpenFile)
         OpenFile.hwndOwner = Form1.hWnd
         OpenFile.hInstance = App.hInstance
         sFilter = "All Files (*.*)" & Chr(0) & "*.*" & Chr(0)
         OpenFile.lpstrFilter = sFilter
         OpenFile.nFilterIndex = 1
         OpenFile.lpstrFile = String(257, 0)
         OpenFile.nMaxFile = Len(OpenFile.lpstrFile) - 1
         OpenFile.lpstrFileTitle = OpenFile.lpstrFile
         OpenFile.nMaxFileTitle = OpenFile.nMaxFile
         OpenFile.lpstrInitialDir = "C:\"
         OpenFile.lpstrTitle = "Use the Comdlg API not the OCX"
         OpenFile.flags = 0
         lReturn = GetOpenFileName(OpenFile)
         If lReturn = 0 Then
            'MsgBox "The User pressed the Cancel Button"
         Else
            OpenFileDialog = Trim(OpenFile.lpstrFile)
         End If
End Function




Sub reloadLV()
    lv.ListItems.Clear
    Dim p As cPatch
    Dim li As ListItem
    
    For Each p In patches
        Set li = lv.ListItems.Add(, , p.Memaddress)
        li.SubItems(1) = Replace(p.Comment, Chr(0), "")
        Set li.Tag = p
    Next
    
End Sub


Private Sub cmdAdd_Click()
    'On Error Resume Next
    
    Dim p As New cPatch
    Dim tmp As String
    
    p.Memaddress = GetMemAddr()
    p.Data = txtHexData
    p.Comment = txtComment
    
    tmp = p.HexStringToBytes(txtHexData)  'throw error if not valid hex and get size
    
    p.Datasize = Len(tmp)
    
    If Err.Number <> 0 Then
        MsgBox "Error: " & Err.Description
    Else
        patches.Add p
        reloadLV
        cmdUpdate.Enabled = False
        cmdRemove.Enabled = False
        txtMemAddress = Empty
        txtHexData = Empty
    End If
    
End Sub

Function StringToHex(b() As Byte) As String
    On Error Resume Next
    Dim ret As String
    
    For i = LBound(b) To UBound(b)
        t = Hex(b(i))
        If Len(t) = 1 Then t = "0" & t
        ret = ret & t
    Next
    
    StringToHex = ret
    
End Function



Private Sub cmdLoad_Click()
        
    On Error GoTo hell
    
    Dim f As Long
    f = FreeFile
    
    Dim p As patch
    Dim pp As cPatch
    
    lv.ListItems.Clear
    Set patches = New Collection
    
    Open txtLoad For Binary As f
    
    Dim r As Long
    For i = 0 To 7
        Get f, , r
        txtReg(i) = Hex(r)
    Next
    
    
    Do While 1
        Get f, , p
        If p.Datasize = 0 Then Exit Do
        Set pp = New cPatch
        pp.Datasize = p.Datasize
        pp.Memaddress = p.Memaddress
        pp.dataOffset = p.foffset
        pp.Comment = p.Comment
        patches.Add pp
    Loop
    
    Dim tmp() As Byte
    
    For Each pp In patches
        ReDim tmp(1 To pp.Datasize)
        Get f, pp.dataOffset + 1, tmp()
        pp.Data = StringToHex(tmp)
    Next
    
    reloadLV
    
    Exit Sub
hell:
    MsgBox Err.Description
    
End Sub

Private Sub cmdRemove_Click()
    
    If selLi Is Nothing Then
        cmdRemove.Enabled = False
        Exit Sub
    End If
    
    Dim p As cPatch
    Dim tmp As cPatch
    
    Dim i As Long
    
    For Each p In patches
        i = i + 1
        Set tmp = selLi.Tag
        If tmp Is p Then
            patches.Remove i
            Exit For
        End If
    Next
    
    txtMemAddress = Empty
    txtHexData = Empty
    
    
    reloadLV
    
End Sub

Sub Align16(ByRef x As Long)
    While x Mod 16 <> 0
        x = x + 1
    Wend
End Sub

Private Sub cmdSaveAs_Click()
        
    On Error GoTo hell
    
    Dim pp() As patch
    Dim p As cPatch
    
    If lv.ListItems.Count = 0 Then
        MsgBox "No patches have been added.", vbInformation
        Exit Sub
    End If
    
    ReDim pp(1 To lv.ListItems.Count + 1)
    
    Dim f_offset As Long
    f_offset = LenB(pp(i)) * UBound(pp) + 32 '+ for registers
    Align16 f_offset
    
    For i = 1 To lv.ListItems.Count
    
        Set p = lv.ListItems(i).Tag
        p.dataOffset = f_offset
        f_offset = f_offset + p.Datasize + 17
        Align16 f_offset
        
        With pp(i)
            .foffset = p.dataOffset
            .Datasize = p.Datasize
            .Memaddress = p.Memaddress
            .Comment = p.Comment
        End With
        
    Next
        
    Dim f As Long
    f = FreeFile
    
    Dim init() As Byte
    ReDim init(p.dataOffset + p.Datasize + 1)
    
    Open txtSave For Binary As f
    Put f, 1, init() 'write out initial file size as all 0's
    
    Seek f, 1
    For i = 0 To 7 'embed the register values
1       Put f, , CLng("&h" & txtReg(i).Text)
    Next
    
    Put f, , pp()   'embed all of the header structures
    
    Dim b() As Byte
    Const LANG_US = &H409
    
    'embed teh actual patch data at proper offsets
    For Each p In patches
        b() = StrConv(p.HexStringToBytes(p.Data), vbFromUnicode, LANG_US)
        Put f, p.dataOffset + 1, b()
    Next
    
    Close f
 
    MsgBox "File Created"
     
    Exit Sub
hell:
    If Erl = 1 Then
        MsgBox "Error register " & (i + 1) & " is not a valid hex number", vbInformation
    Else
        MsgBox "Error: " & Err.Description, vbExclamation
    End If
    
End Sub

Private Sub cmdUpdate_Click()
    
    If selLi Is Nothing Then
        cmdUpdate.Enabled = False
        Exit Sub
    End If
    
    On Error Resume Next
    
    Dim p As cPatch
    Set p = selLi.Tag
    
    p.Memaddress = GetMemAddr()
    
    p.Data = txtHexData
    p.Comment = txtComment
    
    tmp = p.HexStringToBytes(txtHexData)  'throw error if not valid hex and get size
    
    p.Datasize = Len(tmp)
    
    If Err.Number <> 0 Then
        MsgBox "Error: " & Err.Description
    Else
        reloadLV
        cmdUpdate.Enabled = False
        cmdRemove.Enabled = False
        txtMemAddress = Empty
        txtHexData = Empty
    End If
    
    
    
End Sub

Function GetMemAddr() As String
    
    x = txtMemAddress
    x = Replace(x, "0x", "", , , vbTextCompare)
    
    If Len(x) > 8 Then
        x = Mid(x, 1, 8)
    End If
    
    While Len(x) < 8
        x = "0" & x
    Wend
    
    x = x & Chr(0)
    GetMemAddr = x
    
End Function
 
Private Sub Command1_Click()
    txtLoad = OpenFileDialog
    txtSave = txtLoad
    If Len(txtLoad) > 0 Then cmdLoad_Click
End Sub

Private Sub Command2_Click()
    lv.ListItems.Clear
    Set patches = New Collection
    txtComment = Empty
    txtHexData = Empty
    txtMemAddress = Empty
End Sub

Private Sub Form_Load()
     r = Array("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
     v = Array(0, 0, 0, 0, &H12FE00, &H12FFF0, 0, 0)
     For i = 0 To UBound(r)
        lblReg(i).Caption = UCase(r(i))
        txtReg(i).Text = Hex(v(i))
     Next
        
End Sub

Private Sub Label5_Click()
    Dim p As String
    p = OpenFileDialog()
    If Len(p) = 0 Then Exit Sub
     Dim f As Long
    Dim b() As Byte
    
    f = FreeFile
    Open p For Binary As f
    ReDim b(LOF(f))
    Get f, , b()
    Close f
    
    txtHexData = StringToHex(b())

End Sub

Private Sub lv_ItemClick(ByVal Item As MSComctlLib.ListItem)
    Set selLi = Item
    Dim p As cPatch
    Set p = Item.Tag
    txtMemAddress = p.Memaddress
    txtHexData = p.Data
    txtComment = Replace(p.Comment, Chr(0), "")
    cmdUpdate.Enabled = True
    cmdRemove.Enabled = True
End Sub

Private Sub txtHexData_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, x As Single, Y As Single)
    On Error Resume Next
    Dim p As String
    Dim f As Long
    Dim b() As Byte
    
    p = Data.Files(1)
    f = FreeFile
    Open p For Binary As f
    ReDim b(LOF(f))
    Get f, , b()
    Close f
    
    txtHexData = StringToHex(b())
    
    
End Sub

Private Sub txtLoad_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, x As Single, Y As Single)
    On Error Resume Next
    txtLoad = Data.Files(1)
    txtSave = txtLoad
    cmdLoad_Click
End Sub

Private Sub txtReg_GotFocus(Index As Integer)
    On Error Resume Next
    txtReg(Index).SelStart = 0
    txtReg(Index).SelLength = Len(txtReg(Index).Text)
End Sub
