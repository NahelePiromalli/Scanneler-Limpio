import os
import sys
import ctypes
import math
import subprocess
from collections import Counter
import yara
import config  # Importamos nuestro archivo config

# --- FUNCIÓN PARA RUTAS RELATIVAS (NECESARIA PARA NUITKA) ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        try:
            base_path = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def inicializar_yara():
    archivo_reglas = resource_path("reglas_scanneler.yar")
    if os.path.exists(archivo_reglas):
        try:
            config.GLOBAL_YARA_RULES = yara.compile(filepath=archivo_reglas)
            print(f"[OK] Motor YARA cargado: {archivo_reglas}")
        except Exception as e:
            print(f"[ERROR] Fallo al compilar reglas YARA: {e}")
            config.GLOBAL_YARA_RULES = None
    else:
        print("[ALERTA] No se encontró reglas_scanneler.yar. Usando modo degradado.")

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def xor_str(data, key=0x5A):
    """Encrypts / decrypts string data with XOR byte key."""
    if isinstance(data, str):
        return "".join(chr(ord(c) ^ key) for c in data)
    return bytes(b ^ key for b in data)

def check_security():
    """Anti-Debugging & Anti-Tampering Security Engine."""
    try:
        # 1. Direct Win32 IsDebuggerPresent API
        if ctypes.windll.kernel32.IsDebuggerPresent() != 0:
            print("[SECURITY] Debugger detected (IsDebuggerPresent). Exiting.")
            return True

        # 2. Remote Debugger Attached (CheckRemoteDebuggerPresent)
        is_remote_debugger = ctypes.c_bool(False)
        current_proc = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(current_proc, ctypes.byref(is_remote_debugger)):
            if is_remote_debugger.value:
                print("[SECURITY] Remote Debugger detected. Exiting.")
                return True

        # 3. Anti-VM Sandbox Checks (WMI Model query)
        cmd = 'wmic computersystem get model,manufacturer /format:list'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore').lower()
        
        vm_signatures = [
            "virtualbox", "vmware", "kvm", "bhyve", "qemu", 
            "microsoft corporation virtual", "bochs", "pleora", 
            "sibyl", "xen", "parallels"
        ]
        for sig in vm_signatures:
            if sig in output:
                print(f"[SECURITY] Sandbox / Virtual Machine detected: {sig}")
                return True 
    except: 
        pass
    return False

class DisableFileSystemRedirection:
    if os.name == 'nt':
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    else:
        _disable = None; _revert = None
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))
        return self.success
    def __exit__(self, type, value, traceback):
        if self.success: self._revert(self.old_value)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

def get_auth_headers():
    if config.SESSION_TOKEN: return {"Authorization": f"Bearer {config.SESSION_TOKEN}"}
    return {}

def cargar_palabras(ruta_personalizada=None):
    archivo_lista_default = "lista.txt"
    ruta = ruta_personalizada if (ruta_personalizada and os.path.exists(ruta_personalizada)) else archivo_lista_default
    if not os.path.exists(ruta):
        if ruta == archivo_lista_default:
            try:
                with open(ruta, "w", encoding="utf-8") as f: f.write("password\nadmin\nlogin\nsecret\nconfig\nkey\ntoken\n")
            except: pass
        else: return []
    lista_final = []
    try:
        with open(ruta, "r", encoding="utf-8") as f: 
            for line in f:
                if line.strip(): lista_final.append(line.strip().lower())
    except: pass
    return lista_final

def calculate_entropy(data):
    if not data: return 0
    counts = Counter(data)
    length = len(data)
    entropy = 0
    for count in counts.values():
        p_x = count / length
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def filetime_to_dt(ft_dec):
    import datetime
    try:
        us = ft_dec / 10
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
    except: return None

class KernelDriverClient:
    """Interface to communicate Scanneler (User Mode) with Ring 0 Kernel Driver (KMDF) via IOCTL."""
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    IOCTL_SCANNELER_PING = 0x80002000
    IOCTL_SCANNELER_GET_PROCESS_EVENTS = 0x80002004

    def __init__(self, device_path=r"\\.\ScannelerKernel"):
        self.device_path = device_path
        self.handle = None

    def connect(self):
        try:
            self.handle = ctypes.windll.kernel32.CreateFileW(
                self.device_path,
                self.GENERIC_READ | self.GENERIC_WRITE,
                0, None, self.OPEN_EXISTING, 0, None
            )
            return self.handle != -1 and self.handle is not None
        except:
            return False

    def ping_driver(self):
        if not self.handle or self.handle == -1: return False
        out_buf = ctypes.c_ulong()
        bytes_returned = ctypes.c_ulong()
        res = ctypes.windll.kernel32.DeviceIoControl(
            self.handle, self.IOCTL_SCANNELER_PING,
            None, 0,
            ctypes.byref(out_buf), ctypes.sizeof(out_buf),
            ctypes.byref(bytes_returned), None
        )
        return res != 0 and out_buf.value == 0x5343414E

    def close(self):
        if self.handle and self.handle != -1:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

def ensure_kernel_driver_running():
    """Tries to connect to Scanneler Ring 0 Kernel Driver, or start driver service if available."""
    client = KernelDriverClient()
    if client.connect() and client.ping_driver():
        client.close()
        print("[OK] Ring 0 Kernel Driver Active & Monitored")
        return True
    
    # Intento de inicio mediante sc.exe si el driver sys está presente
    sys_path = resource_path("scanneler_kernel_driver.sys")
    if os.path.exists(sys_path):
        try:
            subprocess.run(f'sc create ScannelerKernel binPath= "{sys_path}" type= kernel start= demand', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('sc start ScannelerKernel', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if client.connect() and client.ping_driver():
                client.close()
                print("[OK] Ring 0 Kernel Driver Started Successfully")
                return True
        except: pass
    
    print("[INFO] Operating in User-Mode Standalone Heuristic Mode")
    return False