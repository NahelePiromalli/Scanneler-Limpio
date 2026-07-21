# Archivo: main.py
import sys
import ctypes
import traceback
import tkinter as tk
from tkinter import messagebox

# Intentar importar dependencias críticas
try:
    import customtkinter
    import requests
    from PIL import Image
except ImportError as e:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Error Crítico", f"Faltan librerías.\nEjecuta: pip install customtkinter pillow requests\n\nDetalle: {e}")
    sys.exit()

import utils
import config
from gui import ScannelerApp

if __name__ == "__main__":
    try:
        # 1. Admin Check
        if not utils.is_admin():
            try: ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            except: pass
            sys.exit()

        # 2. Security Check (Anti-Debugging & Anti-Tamper)
        if utils.check_security():
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("Seguridad Activa", "Se ha detectado un entorno de depuración o máquina virtual. Scanneler no se ejecutará en este entorno.")
            sys.exit()
        
        # 3. Cargar YARA & Ring 0 Kernel Driver
        print("Cargando motor...")
        utils.inicializar_yara()
        try: utils.ensure_kernel_driver_running()
        except: pass
        
        # 4. Iniciar App
        app = ScannelerApp()
        app.mainloop()

    except Exception as e:
        # ESTO EVITA QUE SE CIERRE SI HAY ERROR
        err = traceback.format_exc()
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error de Ejecución", f"El programa falló al iniciar:\n\n{err}")
        sys.exit()