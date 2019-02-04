libemu_pe
=============
feature
---------------
1.support run pe file use /exe command

2.add mpr.dll dll hook support

3.add lots of function support

4.support some extra instruction(such as cpuid)

5.3-opcode instruction support


How to run pe file
---------------
scdbg /exe ./test.exe


Screenshot
---------------
![效果图](http://img.arch-vile.com/git-scdbg1.png)


Detail
---------------
NewFunction
```
GetTokenInformation
GetUserDefaultLangID
GetKeyboardLayoutList
GetProcessHeap
HeapAlloc
HeapFree
Process32Next
lstrcmp
ExpandEnvironmentStringsW
lstrcpyW
CryptImportKey
wnsprintf
WNetOpenEnum
wsprintfW
GetLogicalDrives
FindFirstFile
FindNextFile
WaitForMultipleObjects
StrStrI
lstrcmpiW
StrStr
SetFilePointerEx
lstrlenW
lstrlenW
CryptGenRandom
CryptEncrypt
```

Reference
-----------------------------
https://github.com/dzzie/VS_LIBEMU
