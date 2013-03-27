VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CEntry"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Public ID As Long
Public SDate As String
Public ip As String
Public Size As Long
Public MD5 As String
Public scLog As String
Public SC As String
Public LogPath As String
Public SCPath As String
Public Missing As Boolean
Public tvNode As Node
Public ExtractedUrl As String

Function LoadRaw(Data) As Boolean
    '1253    11.15.11 - 4:51am   1xx.2xx.95.116  2274    cc34d9be7ad27b1614ac4daac89343b4
    
    On Error Resume Next
    
    tmp = Split(Data, vbTab)
    ID = CLng(tmp(0))
    SDate = tmp(1)
    ip = tmp(2)
    Size = tmp(3)
    MD5 = tmp(4)
    
    LogPath = Form1.Text1 & "\" & ID & ".sc.txt"
    SCPath = Form1.Text1 & "\" & ID & ".sc"
    
    If FileExists(LogPath) Then
        scLog = ReadFile(LogPath)
        scLog = Replace(scLog, "GetProcAddress(URLDownload", "")
        
        If InStr(scLog, "URLDownload") > 0 Then
            a = InStr(scLog, "URLDownload")
            a = InStr(a, scLog, "(") + 1
            b = InStr(a, scLog, ")")
            X = Mid(scLog, a, b - a)
            ExtractedUrl = Trim(Split(X, ",")(0))
        End If
        
    Else
        LogPath = Empty
        Missing = True
    End If
    
    If FileExists(SCPath) Then
        SC = ReadFile(SCPath)
    Else
        SCPath = Empty
    End If
    
    'LoadRaw = Not Missing
    LoadRaw = True
    
End Function


Function FileExists(path As String) As Boolean
  On Error GoTo hell
  Dim tmp As String
  tmp = Replace(path, "'", Empty)
  tmp = Replace(tmp, """", Empty)
  If Len(tmp) = 0 Then Exit Function
  If Dir(tmp, vbHidden Or vbNormal Or vbReadOnly Or vbSystem) <> "" Then FileExists = True
  Exit Function
hell: FileExists = False
End Function

Function ReadFile(filename) As Variant
  Dim f As Long
  Dim temp As Variant
  f = FreeFile
  temp = ""
   Open filename For Binary As #f        ' Open file.(can be text or image)
     temp = Input(FileLen(filename), #f) ' Get entire Files data
   Close #f
   ReadFile = temp
End Function
