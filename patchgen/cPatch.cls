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

Function HexStringToBytes(X) As String
'    On Error Resume Next
    Dim ret As String
    
    X = Replace(X, " ", "")
    X = Replace(X, vbCr, "")
    X = Replace(X, vbLf, "")
    
    For i = 1 To Len(X) Step 2
        t = Mid(X, i, 2)
        ret = ret & Chr("&h" & t)
    Next
    
    HexStringToBytes = ret
    
End Function


