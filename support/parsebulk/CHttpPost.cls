VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CHttpPost"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Private xmlhttp As Object
Public Initilized As Boolean
Public LastResponse As String
Public BaseUrl As String

'Original Author: Kevin Ritch  7/13/2006
'  http://planet-source-code.com/vb/scripts/ShowCode.asp?txtCodeId=65948&lngWId=1

Private Sub Class_Initialize()
    On Error Resume Next
    Set xmlhttp = CreateObject("MSXML2.ServerXMLHTTP")
    If Err.Number = 0 Then Initilized = True
End Sub

Public Function ToHex(TypedData$) As String
    On Error Resume Next
    tmp$ = ""
    
    For i = 1 To Len(TypedData$)
        n = Asc(Mid$(TypedData$, i, 1))
        HV$ = "00" & Hex$(n)
        HV$ = Right$(HV$, 2)
        tmp$ = tmp$ & HV$
    Next i
    
    ToHex$ = tmp$
    
End Function

Public Function FromHex(TheString) As String
    On Error Resume Next
    
    BYTES = Len(TheString)
    For i = 1 To BYTES
        HV = "&H" & Mid(TheString, i, 2)
        HB = CInt(HV)
        TmpStr = TmpStr & Chr(HB)
        i = i + 1
    Next
    
    FromHex = TmpStr
    
End Function

Private Sub BuildPostData(BYTEARRAY() As Byte, ByVal strPostData As String)

     Dim intNewBytes As Integer
     Dim strCH As String
     Dim i As Integer
     
     intNewBytes = Len(strPostData) - 1
     If intNewBytes < 0 Then Exit Sub
     
     ReDim BYTEARRAY(intNewBytes)
     For i = 0 To intNewBytes
        strCH = Mid$(strPostData, i + 1, 1)
        If strCH = Space(1) Then strCH = "+"
        BYTEARRAY(i) = Asc(strCH)
     Next
     
End Sub

Function DoPost(queryString As String) As Long
     
     Dim bytpostdata() As Byte
     Dim strPostData As String
     Dim varPostData As Variant
     
     If Not Initilized Then
        MsgBox "XmlHttp not properly initilized"
        Exit Function
     End If
     
     If Len(BaseUrl) = 0 Then
        MsgBox "First set BaseURL"
        Exit Function
     End If
    
     BuildPostData bytpostdata(), queryString
     varPostData = bytpostdata
   
     xmlhttp.Open "POST", BaseUrl, False
     xmlhttp.setRequestHeader "Content-Type", "application/x-www-form-urlencoded" & vbCrLf
     xmlhttp.send varPostData
     LastResponse = xmlhttp.responseText
     DoPost = xmlhttp.Status
     
End Function


