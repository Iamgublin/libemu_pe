VERSION 1.0 CLASS
BEGIN
  MultiUse = -1  'True
  Persistable = 0  'NotPersistable
  DataBindingBehavior = 0  'vbNone
  DataSourceBehavior  = 0  'vbNone
  MTSTransactionMode  = 0  'NotAnMTSObject
END
Attribute VB_Name = "CFileSystem2"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = True
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
'Revision 3 <- Incompatiable with all previous..simplified & streamlined
'
'Info:     These are basically macros for VB's built in file processes
'            this should streamline your code quite a bit and hopefully
'            remove alot of redundant coding.
'
'Author:   dzzie@yahoo.com
'Sight:    http://www.geocities.com/dzzie
    
'Changes Jan 5 05
'GetFreeFileName - fixed periodic overflow in
'GetFolderFiles - Added recursive option
'CreateFolder   - now returns boolean
'GetFreeFolderName - Added
'RandomNum - wrapped with 10 try error handling in case of periodic overflow
'Move - changed mechanism of copy to name x as y instead of copy delete
'CreateFile - now returns boolean
'
'changes feb 8 06
'   updated fileexists function to not throw err on bad path

Option Explicit


Function GetFolderFiles(folderPath As String, Optional filter As String = "*", Optional retFullPath As Boolean = True, Optional recursive As Boolean = False) As String()
   Dim fnames() As String
   Dim fs As String
   Dim folders() As String
   Dim i As Integer
   
   If Not FolderExists(folderPath) Then
        'returns empty array if fails
        GetFolderFiles = fnames()
        Exit Function
   End If
   
   folderPath = IIf(Right(folderPath, 1) = "\", folderPath, folderPath & "\")
   
   fs = Dir(folderPath & filter, vbHidden Or vbNormal Or vbReadOnly Or vbSystem)
   While fs <> ""
     If fs <> "" Then push fnames(), IIf(retFullPath = True, folderPath & fs, fs)
     fs = Dir()
   Wend
   
   If recursive Then
        folders() = GetSubFolders(folderPath)
        If Not AryIsEmpty(folders) Then
            For i = 0 To UBound(folders)
                FolderEngine folders(i), fnames(), filter
            Next
        End If
        If Not retFullPath Then
            For i = 0 To UBound(fnames)
                fnames(i) = Replace(fnames(i), folderPath, Empty) 'make relative path from base
            Next
        End If
    End If
   
   GetFolderFiles = fnames()
End Function


Private Sub FolderEngine(fldrpath As String, ary() As String, Optional filter As String = "*")

    Dim files() As String
    Dim folders() As String
    Dim i As Long
     
    files = GetFolderFiles(fldrpath)
    folders = GetSubFolders(fldrpath)
        
    If Not AryIsEmpty(files) Then
        For i = 0 To UBound(files)
            push ary, files(i)
        Next
    End If
    
    If Not AryIsEmpty(folders) Then
        For i = 0 To UBound(folders)
             FolderEngine folders(i), ary, filter
        Next
    End If
    
End Sub

Function GetSubFolders(folderPath As String, Optional retFullPath As Boolean = True) As String()
    Dim fnames() As String
    Dim fd As String
    
    If Not FolderExists(folderPath) Then
        'returns empty array if fails
        GetSubFolders = fnames()
        Exit Function
    End If
    
   If Right(folderPath, 1) <> "\" Then folderPath = folderPath & "\"

   fd = Dir(folderPath, vbDirectory)
   While fd <> ""
     If Left(fd, 1) <> "." Then
        If (GetAttr(folderPath & fd) And vbDirectory) = vbDirectory Then
           push fnames(), IIf(retFullPath = True, folderPath & fd, fd)
        End If
     End If
     fd = Dir()
   Wend
   
   GetSubFolders = fnames()
End Function

Function FolderExists(path As String) As Boolean
  If Len(path) = 0 Then Exit Function
  If Dir(path, vbDirectory) <> "" Then FolderExists = True
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

Function GetParentFolder(path) As String
    Dim tmp() As String
    Dim ub As String
    tmp = Split(path, "\")
    ub = tmp(UBound(tmp))
    GetParentFolder = Replace(Join(tmp, "\"), "\" & ub, "")
End Function


Function CreateFolder(path As String) As Boolean
   On Error GoTo blah
   If FolderExists(path) Then Exit Function
   MkDir path
   If Not FolderExists(path) Then Exit Function
   CreateFolder = True
blah:
End Function

Function FileNameFromPath(fullpath As String) As String
    Dim tmp() As String
    If InStr(fullpath, "\") > 0 Then
        tmp = Split(fullpath, "\")
        FileNameFromPath = CStr(tmp(UBound(tmp)))
    End If
End Function

Function WebFileNameFromPath(fullpath As String)
    Dim tmp() As String
    If InStr(fullpath, "/") > 0 Then
        tmp = Split(fullpath, "/")
        WebFileNameFromPath = CStr(tmp(UBound(tmp)))
    End If
End Function

Function DeleteFile(fpath As String) As Boolean
 On Error GoTo hadErr
    Kill fpath
    DeleteFile = True
 Exit Function
hadErr:
'MsgBox "DeleteFile Failed" & vbCrLf & vbCrLf & fpath
DeleteFile = False
End Function

Sub Rename(fullpath As String, newName As String)
  Dim pf As String
  pf = GetParentFolder(fullpath)
  Name fullpath As pf & "\" & newName
End Sub

Sub SetAttribute(fpath, it As VbFileAttribute)
   SetAttr fpath, it
End Sub

Function GetExtension(path) As String
    Dim tmp() As String
    Dim ub As String
    tmp = Split(path, "\")
    ub = tmp(UBound(tmp))
    If InStr(1, ub, ".") > 0 Then
       GetExtension = Mid(ub, InStrRev(ub, "."), Len(ub))
    Else
       GetExtension = ""
    End If
End Function

Function GetBaseName(path As String) As String
    Dim tmp() As String
    Dim ub As String
    tmp = Split(path, "\")
    ub = tmp(UBound(tmp))
    If InStr(1, ub, ".") > 0 Then
       GetBaseName = Mid(ub, 1, InStrRev(ub, ".") - 1)
    Else
       GetBaseName = ub
    End If
End Function

Function ChangeExt(path As String, ext As String)
    Dim bn As String
    ext = IIf(Left(ext, 1) = ".", ext, "." & ext)
    If FileExists(path) Then
        Rename path, GetBaseName(path) & ext
    Else
        'hack to just accept a file name might not be worth supporting
        bn = Mid(path, 1, InStr(1, path, ".") - 1)
        ChangeExt = bn & ext
    End If
End Function

Function SafeFileName(proposed As String) As String
  Dim badChars As String, bad() As String, i As Long
  badChars = ">,<,&,/,\,:,|,?,*,"""
  bad = Split(badChars, ",")
  For i = 0 To UBound(bad)
    proposed = Replace(proposed, bad(i), "")
  Next
  SafeFileName = CStr(proposed)
End Function

Function RandomNum() As Long
    Dim tmp As Long
    Dim tries As Long
    
    On Error GoTo again
tryit:

    Randomize
    tmp = Round(Timer * Now * Rnd(), 0)
    RandomNum = tmp
    
    Exit Function
again:
    
    If tries < 10 Then
        tries = tries + 1
        GoTo tryit
    End If
    
End Function

Function GetFreeFileName(ByVal folder As String, Optional extension = ".txt") As String
    
    On Error GoTo handler 'can have overflow err once in awhile :(
    Dim i As Integer
    Dim tmp As String

    If Not FolderExists(folder) Then Exit Function
    If Right(folder, 1) <> "\" Then folder = folder & "\"
    If Left(extension, 1) <> "." Then extension = "." & extension
    
again:
    Do
      tmp = folder & RandomNum() & extension
    Loop Until Not FileExists(tmp)
    
    GetFreeFileName = tmp
    
Exit Function
handler:

    If i < 10 Then
        i = i + 1
        GoTo again
    End If
    
End Function


Function GetFreeFolderName(ByVal parentFolder As String, Optional prefix As String = "") As String
    On Error GoTo handler 'can have overflow err once in awhile :(
    Dim i As Integer
    Dim tmp As String

    If Not FolderExists(parentFolder) Then Exit Function
    If Right(parentFolder, 1) <> "\" Then parentFolder = parentFolder & "\"
        
again:
    Do
      tmp = parentFolder & prefix & RandomNum()
    Loop Until Not FolderExists(tmp)
    
    GetFreeFolderName = tmp
    
Exit Function
handler:

    If i < 10 Then
        i = i + 1
        GoTo again
    End If
    
End Function



Function buildPath(folderPath As String) As Boolean
    On Error GoTo oops
    
    If FolderExists(folderPath) Then buildPath = True: Exit Function
    
    Dim tmp() As String, build As String, i As Long
    
    tmp = Split(folderPath, "\")
    build = tmp(0)
    For i = 1 To UBound(tmp)
        build = build & "\" & tmp(i)
        If InStr(tmp(i), ".") < 1 Then
            If Not FolderExists(build) Then CreateFolder (build)
        End If
    Next
    buildPath = True
    Exit Function
oops: buildPath = False
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

Sub WriteFile(path As String, it As Variant)
    Dim f As Long
    f = FreeFile
    Open path For Output As #f
    Print #f, it
    Close f
End Sub

Sub AppendFile(path, it)
    Dim f As Long
    f = FreeFile
    Open path For Append As #f
    Print #f, it
    Close f
End Sub


Function Copy(fpath As String, toFolder As String)
   Dim baseName As String, newName As String
   If FolderExists(toFolder) Then
       baseName = FileNameFromPath(fpath)
       toFolder = IIf(Right(toFolder, 1) = "\", toFolder, toFolder & "\")
       newName = toFolder & baseName
       FileCopy fpath, newName
       Copy = newName
   Else 'assume tofolder is actually new desired file path
       FileCopy fpath, toFolder
       Copy = toFolder
   End If
End Function

Function Move(fpath As String, toFolder As String)
    Dim fname As String
    fname = FileNameFromPath(fpath)
    toFolder = IIf(Right(toFolder, 1) = "\", toFolder, toFolder & "\")
    
    Name fpath As toFolder & fname
    Move = toFolder & fname
    
End Function

Function CreateFile(fpath As String) As Boolean
    On Error GoTo hell
    Dim f As Long
    f = FreeFile
    If FileExists(fpath) Then Exit Function
    Open fpath For Binary As f
    Close f
    If FileExists(fpath) Then CreateFile = True
hell:
End Function


Function DeleteFolder(folderPath As String, Optional force As Boolean = True) As Boolean
 On Error GoTo failed
   Call delTree(folderPath, force)
   RmDir folderPath
   DeleteFolder = True
 Exit Function
failed:  DeleteFolder = False
End Function

Private Sub delTree(folderPath As String, Optional force As Boolean = True)
   Dim sfi() As String, sfo() As String, i As Integer
   sfi() = GetFolderFiles(folderPath)
   sfo() = GetSubFolders(folderPath)
   If Not AryIsEmpty(sfi) And force = True Then
        For i = 0 To UBound(sfi)
            Kill sfi(i)
        Next
   End If
   
   If Not AryIsEmpty(sfo) And force = True Then
        For i = 0 To UBound(sfo)
            Call DeleteFolder(sfo(i), True)
        Next
   End If
End Sub

Private Sub push(ary, value) 'this modifies parent ary object
    On Error GoTo init
    Dim x As Long
    x = UBound(ary) '<-throws Error If Not initalized
    ReDim Preserve ary(UBound(ary) + 1)
    ary(UBound(ary)) = value
    Exit Sub
init: ReDim ary(0): ary(0) = value
End Sub

Private Function AryIsEmpty(ary) As Boolean
  On Error GoTo oops
    Dim x As Long
    x = UBound(ary)
    AryIsEmpty = False
  Exit Function
oops: AryIsEmpty = True
End Function

Function FolderName(folderPath) As String
    Dim ret As String, tmp() As String
    tmp = Split(folderPath, "\")
    If Not AryIsEmpty(tmp) Then
        If Len(tmp(UBound(tmp))) <> 0 Then ret = tmp(UBound(tmp)) _
        Else ret = tmp(UBound(tmp) - 1)
    Else
        ret = CStr(folderPath)
    End If
    FolderName = ret
End Function


Private Sub Class_Initialize()
   ' If Not isRegistered And Not isInitalized Then TellThemAllAboutIt
End Sub
