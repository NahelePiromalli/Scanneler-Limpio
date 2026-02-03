import sys
import ctypes
import utils
import config
from gui import ScannelerApp

if __name__ == "__main__":
    if not utils.is_admin():
        try: ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except: pass
        sys.exit()

    if utils.check_security():
        sys.exit()
    
    print("Cargando motor de detección...")
    utils.inicializar_yara()
    
    app = ScannelerApp()
    app.mainloop()