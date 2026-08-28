Option Explicit

Dim objShell, objFSO, objHTTP, objStream
Dim strURL, strZipPath, strExtractPath, strTempFolder, strPythonExe, objFile

' 1. Сначала СТРОГО создаем базовые объекты автоматизации
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' 2. Используем системную папку TEMP — это гарантирует 100% прав на запись
strTempFolder = objShell.ExpandEnvironmentStrings("%TEMP%")
strExtractPath = strTempFolder & "\python_update"
strZipPath = strExtractPath & "\python.zip"

strURL = "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip"

' 3. Создаем рабочую директорию, если её нет
If Not objFSO.FolderExists(strExtractPath) Then
    objFSO.CreateFolder(strExtractPath)
End If

' 4. Скачиваем архив
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "GET", strURL, False
objHTTP.Send

If objHTTP.Status = 200 Then
    ' Сохраняем бинарный поток на диск
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Open
    objStream.Type = 1 ' adTypeBinary
    objStream.Write objHTTP.ResponseBody
    objStream.SaveToFile strZipPath, 2 ' adSaveCreateOverWrite
    objStream.Close
    
    ' 5. Распаковываем ZIP через скрытое окно PowerShell (параметр 0 скрывает окно)
    objShell.Run "powershell -WindowStyle Hidden -Command ""Expand-Archive -Path '" & strZipPath & "' -DestinationPath '" & strExtractPath & "' -Force""", 0, True
    
    ' Удаляем архив после распаковки
    If objFSO.FileExists(strZipPath) Then
        objFSO.DeleteFile strZipPath
    End If
    
    ' 6. Создаем тестовый python-скрипт
    Set objFile = objFSO.CreateTextFile(strExtractPath & "\calc.py", True)
    objFile.WriteLine "import subprocess"
    objFile.WriteLine "subprocess.run(['calc.exe'])"
    objFile.Close
    
    ' 7. Запускаем калькулятор через скачанный Python
    strPythonExe = strExtractPath & "\python.exe"
    
    ' Запуск в видимом окне (1), скрипт VBS не ждет завершения (False)
    objShell.Run """" & strPythonExe & """ """ & strExtractPath & "\calc.py""", 1, False
End If
