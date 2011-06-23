VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "cPatch"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Public dataOffset As Long
Public Datasize As Long
Public Data As String
Public Memaddress As String
Private mComment As String

Property Get Comment() As String
    Comment = mComment
End Property

Property Let Comment(ByVal x As String)
    If Len(x) > 15 Then x = Mid(x, 1, 15)
    While Len(x) < 16
        x = x & Chr(0)
    Wend
    mComment = x
End Property

Function HexStringToBytes(x) As String
'    On Error Resume Next
    Dim ret As String
    
    x = Replace(x, " ", "")
    x = Replace(x, vbCr, "")
    x = Replace(x, vbLf, "")
    
    For i = 1 To Len(x) Step 2
        t = Mid(x, i, 2)
        ret = ret & Chr("&h" & t)
    Next
    
    HexStringToBytes = ret
    
End Function


