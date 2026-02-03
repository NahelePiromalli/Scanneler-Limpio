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

        # 2. Security Check (Anti-VM)
        # if utils.check_security(): sys.exit() # Descomentar para producción
        
        # 3. Cargar YARA
        print("Cargando motor...")
        utils.inicializar_yara()
        
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