import asyncio
import json
import socket
import websockets

# Список подключенных браузеров-зрителей
viewers = set()

# 1. Обработчик подключений от браузера (Порт 8081)
async def handle_browser(websocket):
    global viewers
    viewers.add(websocket)
    print(f"[Браузер] Зритель подключился. Всего: {len(viewers)}")
    try:
        await websocket.wait_closed()
    finally:
        viewers.remove(websocket)
        print(f"[Браузер] Зритель отключился. Осталось: {len(viewers)}")

# Функция для рассылки кадров и звука всем браузерам
async def broadcast_to_browsers(message_str):
    if not viewers:
        return
    # Рассылаем параллельно всем открытым index.html
    await asyncio.gather(
        *[asyncio.create_task(viewer.send(message_str)) for viewer in viewers],
        return_exceptions=True
    )

# 2. Асинхронный TCP-сервер для C# стримера (Порт 8080)
async def start_tcp_receiver():
    # Создаем неблокирующий TCP сокет
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind(('0.0.0.0', 8080))
    tcp_server.listen(1)
    tcp_server.setblocking(False)
    
    loop = asyncio.get_event_loop()
    print("--------------------------------------------------")
    print("1. TCP-приемник запущен на порту 8080 (Сюда слать туннель Pinggy t.pinggy.io)")
    print("2. WebSocket-вещатель запущен на порту 8081 (Сюда подключать index.html)")
    print("--------------------------------------------------")

    while True:
        conn, addr = await loop.sock_accept(tcp_server)
        print(f"[C# Стример] Подключился клиент: {addr}")
        
        buffer = ""
        while True:
            try:
                # Получаем сырые данные из TCP-туннеля
                data_bytes = await loop.sock_recv(conn, 65536)
                if not data_bytes:
                    break
                
                # Декодируем, отсекая возможный BOM-маркер .NET
                data_str = data_bytes.decode('utf-8-sig', errors='ignore')
                buffer += data_str
                
                # Нарезаем поток данных по символу \n
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    
                    # Мгновенно пересылаем JSON-строку в веб-сокеты браузеров
                    await broadcast_to_browsers(line)
                    
            except Exception as e:
                print(f"[C# Стример] Ошибка или обрыв соединения: {e}")
                break
        
        conn.close()
        print("[C# Стример] Соединение закрыто. Ожидание нового подключения...")

async def main():
    # Запускаем WebSocket-сервер для браузера на порту 8081
    async with websockets.serve(handle_browser, "0.0.0.0", 8081, ping_interval=None, ping_timeout=None):
        # Параллельно запускаем TCP-сервер на порту 8080
        await start_tcp_receiver()

if __name__ == "__main__":
    asyncio.run(main())