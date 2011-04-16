VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form1 
   Caption         =   "scdbg Patch Viewer/Generator"
   ClientHeight    =   4860
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   8205
   LinkTopic       =   "Form1"
   ScaleHeight     =   4860
   ScaleWidth      =   8205
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton Command2 
      Caption         =   "New"
      Height          =   285
      Left            =   6705
      TabIndex        =   16
      Top             =   540
      Width           =   1410
   End
   Begin VB.CommandButton Command1 
      Caption         =   "..."
      Height          =   285
      Left            =   5805
      TabIndex        =   15
      Top             =   135
      Width           =   780
   End
   Begin MSComctlLib.ListView lv 
      Height          =   3840
      Left            =   90
      TabIndex        =   13
      Top             =   540
      Width           =   1860
      _ExtentX        =   3281
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
      NumItems        =   1
      BeginProperty ColumnHeader(1) {BDD1F052-858B-11D1-B16A-00C0F0283628} 
         Text            =   "Patches"
         Object.Width           =   2540
      EndProperty
   End
   Begin VB.CommandButton cmdRemove 
      Caption         =   "Remove"
      Height          =   375
      Left            =   4365
      TabIndex        =   12
      Top             =   3960
      Width           =   1365
   End
   Begin VB.CommandButton cmdUpdate 
      Caption         =   "Update"
      Enabled         =   0   'False
      Height          =   375
      Left            =   6885
      TabIndex        =   11
      Top             =   3960
      Width           =   1275
   End
   Begin VB.CommandButton cmdSaveAs 
      Caption         =   "Save As"
      Height          =   330
      Left            =   6885
      TabIndex        =   10
      Top             =   4455
      Width           =   1275
   End
   Begin VB.TextBox txtSave 
      Height          =   315
      Left            =   570
      TabIndex        =   9
      Top             =   4455
      Width           =   6150
   End
   Begin VB.CommandButton cmdAdd 
      Caption         =   "Insert"
      Height          =   375
      Left            =   2160
      TabIndex        =   7
      Top             =   4005
      Width           =   1275
   End
   Begin VB.TextBox txtHexData 
      Height          =   2490
      Left            =   2025
      MultiLine       =   -1  'True
      OLEDropMode     =   1  'Manual
      ScrollBars      =   2  'Vertical
      TabIndex        =   6
      Top             =   1350
      Width           =   6045
   End
   Begin VB.TextBox txtMemAddress 
      Height          =   330
      Left            =   3240
      MaxLength       =   8
      TabIndex        =   4
      Top             =   585
      Width           =   1455
   End
   Begin VB.CommandButton cmdLoad 
      Caption         =   "Load Existing"
      Height          =   330
      Left            =   6705
      TabIndex        =   2
      Top             =   135
      Width           =   1410
   End
   Begin VB.TextBox txtLoad 
      Height          =   315
      Left            =   480
      TabIndex        =   1
      Text            =   "Drag and Drop file here"
      Top             =   120
      Width           =   5295
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
      Left            =   7380
      TabIndex        =   14
      Top             =   1080
      Width           =   690
   End
   Begin VB.Label Label4 
      Caption         =   "File"
      Height          =   255
      Left            =   90
      TabIndex        =   8
      Top             =   4500
      Width           =   735
   End
   Begin VB.Label Label3 
      Caption         =   "HexData  (can also drop file to load)"
      Height          =   285
      Left            =   2070
      TabIndex        =   5
      Top             =   1035
      Width           =   4020
   End
   Begin VB.Label Label2 
      Caption         =   "Hex MemAddr"
      Height          =   240
      Left            =   2070
      TabIndex        =   3
      Top             =   630
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
         sFilter = "Batch Files (*.bat)" & Chr(0) & "*.BAT" & Chr(0)
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
        Set li.Tag = p
    Next
    
End Sub


Private Sub cmdAdd_Click()
    'On Error Resume Next
    
    Dim p As New cPatch
    Dim tmp As String
    
    p.Memaddress = GetMemAddr()
    p.Data = txtHexData
    
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
    Do While 1
        Get f, , p
        If p.Datasize = 0 Then Exit Do
        Set pp = New cPatch
        pp.Datasize = p.Datasize
        pp.Memaddress = p.Memaddress
        pp.dataOffset = p.foffset
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

Sub Align16(ByRef X As Long)
    While X Mod 16 <> 0
        X = X + 1
    Wend
End Sub

Private Sub cmdSaveAs_Click()
        
    On Error GoTo hell
    
    Dim pp() As patch
    Dim p As cPatch
    
    ReDim pp(1 To lv.ListItems.Count + 1)
    
    Dim f_offset As Long
    f_offset = LenB(pp(i)) * UBound(pp)
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
        End With
        
    Next
        
    Dim f As Long
    f = FreeFile
    
    Dim init() As Byte
    ReDim init(p.dataOffset + p.Datasize + 1)
    
    Open txtSave For Binary As f
    Put f, 1, init() 'write out initial file size as all 0's
    Put f, 1, pp()   'embed all of the header structures
    
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
    MsgBox "Error: " & Err.Description, vbExclamation
    
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
    
    X = txtMemAddress
    X = Replace(X, "0x", "", , , vbTextCompare)
    
    If Len(X) > 8 Then
        X = Mid(X, 1, 8)
    End If
    
    While Len(X) < 8
        X = "0" & X
    Wend
    
    X = X & Chr(0)
    GetMemAddr = X
    
End Function
 
Private Sub Command1_Click()
    txtLoad = OpenFileDialog
    txtSave = txtLoad
    If Len(txtLoad) > 0 Then cmdLoad_Click
End Sub

Private Sub Command2_Click()
    lv.ListItems.Clear
    Set patches = New Collection
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
    cmdUpdate.Enabled = True
    cmdRemove.Enabled = True
End Sub

Private Sub txtHexData_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
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

Private Sub txtLoad_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    On Error Resume Next
    txtLoad = Data.Files(1)
    txtSave = txtLoad
    cmdLoad_Click
End Sub
