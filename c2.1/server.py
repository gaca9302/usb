import os
from flask import Flask, request, send_from_directory
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['POST'])
def receive_message():
    message = request.data.decode('utf-8')
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{current_time}] {message}\n"
    with open("file.log", "a", encoding="utf-8") as f:
        f.write(log_entry)
    return "Message saved!", 200

@app.route('/bin.txt', methods=['GET'])
def get_task():
    current_dir = os.getcwd() 
    return send_from_directory(current_dir, 'bin.txt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
