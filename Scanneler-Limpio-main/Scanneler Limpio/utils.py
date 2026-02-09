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

def check_security():
    try:
        cmd = 'wmic computersystem get model,manufacturer /format:list'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore').lower()
        
        vm_signatures = [
            "virtualbox", "vmware", "kvm", "bhyve", "qemu", 
            "microsoft corporation virtual", "bochs", "pleora", 
            "sibyl", "xen", "parallels"
        ]
        
        for sig in vm_signatures:
            if sig in output:
                return True 

        is_debugger = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger != 0:
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