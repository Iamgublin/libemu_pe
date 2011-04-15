VERSION 5.00
Object = "{831FDD16-0C5C-11D2-A9FC-0000F8754DA1}#2.0#0"; "mscomctl.ocx"
Begin VB.Form Form1 
   Caption         =   "scdbg Patch Viewer/Generator"
   ClientHeight    =   4860
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   7365
   LinkTopic       =   "Form1"
   ScaleHeight     =   4860
   ScaleWidth      =   7365
   StartUpPosition =   3  'Windows Default
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
      Left            =   4050
      TabIndex        =   12
      Top             =   4005
      Width           =   1365
   End
   Begin VB.CommandButton cmdUpdate 
      Caption         =   "Update"
      Enabled         =   0   'False
      Height          =   375
      Left            =   6030
      TabIndex        =   11
      Top             =   4005
      Width           =   1275
   End
   Begin VB.CommandButton cmdSaveAs 
      Caption         =   "Save As"
      Height          =   330
      Left            =   6030
      TabIndex        =   10
      Top             =   4455
      Width           =   1275
   End
   Begin VB.TextBox txtSave 
      Height          =   315
      Left            =   570
      TabIndex        =   9
      Top             =   4455
      Width           =   5295
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
      Left            =   2115
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   6
      Top             =   1395
      Width           =   5145
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
      Left            =   5895
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
   Begin VB.Label Label4 
      Caption         =   "File"
      Height          =   255
      Left            =   90
      TabIndex        =   8
      Top             =   4500
      Width           =   735
   End
   Begin VB.Label Label3 
      Caption         =   "HexData"
      Height          =   285
      Left            =   2070
      TabIndex        =   5
      Top             =   1035
      Width           =   915
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
        
    On Error Resume Next
    
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

    If Err.Number <> 0 Then
        MsgBox "Error: " & Err.Description
    Else
        MsgBox "File Created"
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
 
Private Sub lv_ItemClick(ByVal Item As MSComctlLib.ListItem)
    Set selLi = Item
    Dim p As cPatch
    Set p = Item.Tag
    txtMemAddress = p.Memaddress
    txtHexData = p.Data
    cmdUpdate.Enabled = True
    cmdRemove.Enabled = True
End Sub

Private Sub txtLoad_OLEDragDrop(Data As DataObject, Effect As Long, Button As Integer, Shift As Integer, X As Single, Y As Single)
    On Error Resume Next
    txtLoad = Data.Files(1)
    txtSave = txtLoad
End Sub
