VERSION 5.00
Begin VB.Form frmApi2IDC 
   Caption         =   "Convert API Logs into IDC scripts"
   ClientHeight    =   6360
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   12270
   LinkTopic       =   "Form1"
   ScaleHeight     =   6360
   ScaleWidth      =   12270
   StartUpPosition =   2  'CenterScreen
   Begin VB.CheckBox Check1 
      Caption         =   "strip 0x401 offsets"
      Height          =   255
      Left            =   8880
      TabIndex        =   3
      Top             =   5940
      Value           =   1  'Checked
      Width           =   1575
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Make IDC"
      Height          =   375
      Left            =   10680
      TabIndex        =   2
      Top             =   5880
      Width           =   1455
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Courier New"
         Size            =   12
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   5415
      Left            =   0
      MultiLine       =   -1  'True
      ScrollBars      =   3  'Both
      TabIndex        =   1
      Text            =   "frmApi2IDC.frx":0000
      Top             =   360
      Width           =   12135
   End
   Begin VB.Label Label2 
      Caption         =   "example input"
      BeginProperty Font 
         Name            =   "MS Sans Serif"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   -1  'True
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00C00000&
      Height          =   255
      Left            =   960
      TabIndex        =   4
      Top             =   6000
      Width           =   1215
   End
   Begin VB.Label Label1 
      Caption         =   "Api Log"
      Height          =   255
      Left            =   0
      TabIndex        =   0
      Top             =   0
      Width           =   735
   End
End
Attribute VB_Name = "frmApi2IDC"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Dim example As String


Private Sub Command1_Click()
    
    Dim r As String
    
    On Error Resume Next
    tmp = Split(Text1, vbCrLf)
    For Each X In tmp
        a = InStr(X, "  ")
        If a > 0 Then
            t2 = Split(X, "  ")
            Y = Replace(Trim(t2(1)), """", "")
            Y = Replace(Y, "\", "\\")
            r = r & "MakeComm(0x" & t2(0) & ", """ & Y & """);" & vbCrLf
        End If
    Next
    
    If Check1.Value = 1 Then
        r = Replace(r, "0x401", "0x")
    End If
    
    Text1 = r
    Text1.SetFocus
    Text1.SelStart = 0
    Text1.SelLength = Len(Text1)
    
    
End Sub

Private Sub Form_Load()
    example = Text1
    Text1 = Empty
End Sub

Private Sub Label2_Click()
    Text1 = example
End Sub
