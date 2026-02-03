import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import threading
import sys
import os
import requests  # <--- IMPORTANTE
import datetime
import random
import time      # <--- IMPORTANTE (Soluciona el error de linea 73)
from queue import Queue

# Importaciones locales
import config
import utils
import scanner_engine

# Intentar importar PIL
try:
    from PIL import Image, ImageTk
except ImportError: pass

# =============================================================================
# [UI COMPONENTS] BOTONES Y ALERTAS
# =============================================================================

class CyberRain:
    def __init__(self, canvas, color_accent):
        self.canvas = canvas; self.color = color_accent; self.drops = []; self.width = 3000; self.height = 2000; self.is_running = True; self.after_id = None; self.crear_gotas(); self.animar()
    def crear_gotas(self):
        try:
            for _ in range(120): 
                x = random.randint(0, self.width); y = random.randint(-500, self.height); speed = random.randint(2, 6); char = random.choice(["1", "0", "X", "S", "C", "A", "N"]); rain_color = random.choice([config.COLOR_ACCENT, config.COLOR_USER, "#7c4dff", "#e040fb"])
                if random.random() > 0.8: rain_color = "white"
                tag = self.canvas.create_text(x, y, text=char, fill=rain_color, font=("Consolas", 9, "bold"), tag="rain"); self.drops.append([tag, speed, y])
        except: pass
    def animar(self):
        if not self.is_running: return
        try:
            if not self.canvas.winfo_exists(): self.is_running = False; return
            h = 1500 
            for i in range(len(self.drops)):
                tag, speed, y = self.drops[i]; y += speed
                if y > h: y = random.randint(-100, 0); self.canvas.coords(tag, random.randint(0, self.width), y)
                else: self.canvas.move(tag, 0, speed)
                self.drops[i][2] = y
            if self.is_running: self.after_id = self.canvas.after(30, self.animar)
        except: self.is_running = False
    def detener(self):
        self.is_running = False
        if self.after_id:
            try: self.canvas.after_cancel(self.after_id); self.after_id = None
            except: pass

class BotonCanvas:
    def __init__(self, canvas, x, y, width, height, text, color_accent, command):
        self.canvas = canvas; self.x = x; self.y = y; self.w = width; self.h = height; self.text = text; self.cmd = command
        self.c_border = color_accent; self.c_fill = "#1a0526"; self.c_text = config.COLOR_TEXT; self.c_hover = config.COLOR_HOVER_BG; self.c_hover_border = config.COLOR_HOVER_BORDER
        self.id_shadow = self.canvas.create_line(x - width/2 + height/2, y + 4, x + width/2 - height/2, y + 4, width=height, fill="#000000", capstyle="round", stipple="gray50")
        self.id_glow = self.canvas.create_line(x - width/2 + height/2, y, x + width/2 - height/2, y, width=height, fill=self.c_border, capstyle="round")
        self.id_body = self.canvas.create_line(x - width/2 + height/2, y, x + width/2 - height/2, y, width=height-4, fill=self.c_fill, capstyle="round")
        self.id_text_s = self.canvas.create_text(x+1, y+1, text=text, fill="black", font=("Consolas", 11, "bold"))
        self.id_text = self.canvas.create_text(x, y, text=text, fill=self.c_text, font=("Consolas", 11, "bold"))
        self.items = [self.id_shadow, self.id_glow, self.id_body, self.id_text_s, self.id_text]
        for item in self.items:
            self.canvas.tag_bind(item, "<Enter>", self.on_enter); self.canvas.tag_bind(item, "<Leave>", self.on_leave); self.canvas.tag_bind(item, "<Button-1>", self.on_click); self.canvas.tag_bind(item, "<ButtonRelease-1>", self.on_release)
    def move_to(self, new_x, new_y):
        dx = new_x - self.x; dy = new_y - self.y
        for item in self.items: self.canvas.move(item, dx, dy)
        self.x = new_x; self.y = new_y
    def on_enter(self, e): self.canvas.itemconfig(self.id_body, fill=self.c_hover); self.canvas.itemconfig(self.id_glow, fill=self.c_hover_border); self.canvas.itemconfig(self.id_glow, width=self.h+2); self.canvas.itemconfig(self.id_text, fill="white")
    def on_leave(self, e): self.canvas.itemconfig(self.id_body, fill=self.c_fill); self.canvas.itemconfig(self.id_glow, fill=self.c_border); self.canvas.itemconfig(self.id_glow, width=self.h); self.canvas.itemconfig(self.id_text, fill=self.c_text)
    def on_click(self, e):
        self.canvas.itemconfig(self.id_body, fill="#000000"); self.canvas.update_idletasks(); time.sleep(0.05); self.canvas.itemconfig(self.id_body, fill=self.c_hover)
        if self.cmd: self.cmd()
    def on_release(self, e): self.on_enter(e)

class BotonDinamico(tk.Button):
    def __init__(self, master, color_accent, **kwargs):
        super().__init__(master, **kwargs); self.accent = color_accent; self.default_bg = kwargs.get("bg", config.COLOR_CARD)
        self.config(bg=self.default_bg, fg=config.COLOR_TEXT, font=("Consolas", 10, "bold"), relief="flat", bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER, padx=20, pady=10, cursor="hand2", activebackground=self.accent, activeforeground="black")
        self.bind("<Enter>", self.hover_in); self.bind("<Leave>", self.hover_out)
    def hover_in(self, e): self.config(highlightbackground=self.accent, bg=config.COLOR_HOVER_BG, fg="white")
    def hover_out(self, e): self.config(highlightbackground=config.COLOR_BORDER, bg=self.default_bg, fg=config.COLOR_TEXT)

class ModernAlert:
    def __init__(self, title, message, type="info", parent=None):
        self.result = False; self.top = tk.Toplevel(parent); self.top.overrideredirect(True); self.top.config(bg=config.COLOR_BG); self.top.attributes("-topmost", True)
        w, h = 450, 220; sw, sh = self.top.winfo_screenwidth(), self.top.winfo_screenheight(); self.top.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        color = config.COLOR_DANGER if type == "error" else config.COLOR_ACCENT
        main_frame = tk.Frame(self.top, bg=config.COLOR_BG, highlightthickness=2, highlightbackground=color); main_frame.pack(fill="both", expand=True)
        tk.Label(main_frame, text=f"// {title.upper()} //", bg=config.COLOR_BG, fg=color, font=("Consolas", 14, "bold")).pack(pady=(25, 10))
        tk.Label(main_frame, text=message, bg=config.COLOR_BG, fg=config.COLOR_TEXT, font=("Consolas", 10), wraplength=400).pack(pady=10)
        btn_frame = tk.Frame(main_frame, bg=config.COLOR_BG); btn_frame.pack(pady=20)
        if type == "ask":
            BotonDinamico(btn_frame, config.COLOR_ACCENT, text="CONFIRM", command=self.on_yes, width=15).pack(side="left", padx=15)
            BotonDinamico(btn_frame, config.COLOR_DANGER, text="CANCEL", command=self.on_no, width=15).pack(side="left", padx=15)
        else: BotonDinamico(btn_frame, color, text="ACKNOWLEDGE", command=self.on_close, width=15).pack()
        self.top.grab_set(); self.top.wait_window()
    def on_yes(self): self.result = True; self.top.destroy()
    def on_no(self): self.result = False; self.top.destroy()
    def on_close(self): self.top.destroy()

def show_info(title, msg): ModernAlert(title, msg, "info")
def show_error(title, msg): ModernAlert(title, msg, "error")
def ask_yes_no(title, msg): alert = ModernAlert(title, msg, "ask"); return alert.result

def aplicar_estilo_combobox(root):
    style = ttk.Style()
    try: style.theme_use('clam')
    except: pass
    style.configure("TCombobox", fieldbackground=config.COLOR_CARD, background=config.COLOR_BG, foreground=config.COLOR_TEXT, arrowcolor=config.COLOR_ACCENT, bordercolor=config.COLOR_BORDER)
    style.map("TCombobox", fieldbackground=[('readonly', config.COLOR_CARD)], selectbackground=[('readonly', config.COLOR_CARD)], selectforeground=[('readonly', config.COLOR_ACCENT)])
    root.option_add('*TCombobox*Listbox.background', "#2a0a38")
    root.option_add('*TCombobox*Listbox.foreground', config.COLOR_TEXT)
    root.option_add('*TCombobox*Listbox.selectBackground', config.COLOR_ACCENT)
    root.option_add('*TCombobox*Listbox.selectForeground', 'white')

# =============================================================================
# FRAMES Y VENTANAS
# =============================================================================

class VentanaRegistro:
    def __init__(self, parent_root):
        self.win = tk.Toplevel(parent_root); self.win.title("LICENSE REDEMPTION"); self.win.geometry("450x650"); self.win.configure(bg=config.COLOR_BG)
        self.win.transient(parent_root); self.win.grab_set()
        tk.Label(self.win, text="ACTIVATE SCANNELER", font=("Consolas", 18, "bold"), bg=config.COLOR_BG, fg=config.COLOR_ACCENT).pack(pady=30)
        container = tk.Frame(self.win, bg=config.COLOR_CARD, padx=30, pady=30, highlightthickness=1, highlightbackground=config.COLOR_BORDER); container.pack(padx=20, fill="x")
        tk.Label(container, text="LICENSE KEY:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_key = tk.Entry(container, bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_key.pack(fill="x", pady=(5, 15), ipady=8); self.entry_key.insert(0, "SCAN-XXXX-XXXX")
        tk.Label(container, text="NEW USERNAME:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_u = tk.Entry(container, bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_u.pack(fill="x", pady=(5, 15), ipady=8)
        tk.Label(container, text="NEW PASSWORD:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_p = tk.Entry(container, show="*", bg="#0f0018", fg="white", bd=0, insertbackground="white", font=("Consolas", 11), justify="center"); self.entry_p.pack(fill="x", pady=(5, 25), ipady=8)
        BotonDinamico(self.win, config.COLOR_ACCENT, text="ACTIVATE & REGISTER", command=self.enviar_registro, width=35).pack(pady=20)
        BotonDinamico(self.win, config.COLOR_DANGER, text="CANCEL", command=self.win.destroy, width=35).pack()

    def enviar_registro(self):
        k = self.entry_key.get().strip(); u = self.entry_u.get().strip(); p = self.entry_p.get().strip()
        if not k or not u or not p or k == "SCAN-XXXX-XXXX": show_error("Error", "Complete all fields."); return
        try:
            resp = requests.post(f"{config.API_URL}/keys/redeem", json={"key_code": k, "username": u, "password": p}, timeout=15)
            if resp.status_code == 201: show_info("Success", "Account created! Now you can log in."); self.win.destroy()
            else: show_error("Failed", f"Activation Error: {resp.json().get('detail', 'Invalid Key')}")
        except Exception as e: show_error("Error", f"Connection failed: {e}")

class ScannelerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SCANNELER")
        self.geometry("900x700")
        self.configure(bg=config.COLOR_BG)
        aplicar_estilo_combobox(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.container = tk.Frame(self, bg=config.COLOR_BG)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        self.current_frame = None
        self.switch_frame(CargaDinamicaFrame)

    def switch_frame(self, frame_class, *args, **kwargs):
        if self.current_frame:
            if hasattr(self.current_frame, 'cleanup'):
                self.current_frame.cleanup()
            self.current_frame.destroy()
        self.current_frame = frame_class(self.container, self, *args, **kwargs)
        self.current_frame.grid(row=0, column=0, sticky="nsew")

    def on_close(self):
        config.CANCELAR_ESCANEO = True
        self.destroy()
        sys.exit()

class CargaDinamicaFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, config.COLOR_ACCENT)
        self.elements = []
        archivo_logo = utils.resource_path("Scanneler.png")

        try: 
            from PIL import Image, ImageTk
            self.pir = Image.open(archivo_logo)
            self.pir = self.pir.resize((300, 250), Image.Resampling.LANCZOS)
            self.il = ImageTk.PhotoImage(self.pir)
            self.logo_id = self.canvas.create_image(450, 300, image=self.il)
            self.canvas.bind("<Configure>", self.center_content) 
        except Exception as e: 
            self.logo_id = self.canvas.create_text(450, 300, text="[ SCANNELER ]", fill="#d500f9", font=("Consolas", 30, "bold"))
            
        self.text_id = self.canvas.create_text(550, 450, text="INICIANDO SISTEMA...", fill="#d500f9", font=("Consolas", 14, "bold"))
        self.canvas.bind("<Configure>", self.center_content)
        self.after(500, self.iniciar_carga)

    def center_content(self, event):
        w, h = event.width, event.height
        cx, cy = w/2, h/2
        self.canvas.coords(self.logo_id, cx, cy - 50)
        self.canvas.coords(self.text_id, cx, cy + 100)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def iniciar_carga(self):
        self.canvas.itemconfig(self.text_id, text="CARGANDO MOTOR YARA...")
        self.update_idletasks()
        utils.inicializar_yara()
        self.canvas.itemconfig(self.text_id, text="SISTEMA LISTO.")
        self.update_idletasks()
        self.after(1000, self.go_login)

    def go_login(self):
        self.controller.switch_frame(LoginFrame)

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, "#00ff41")
        self.content = tk.Frame(self.canvas, bg=config.COLOR_BG)
        self.wid = self.canvas.create_window(450, 350, window=self.content, anchor="center") 
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))
        
        tk.Label(self.content, text=config.t("login_title"), font=("Consolas", 18, "bold"), bg=config.COLOR_BG, fg=config.COLOR_ACCENT).pack(pady=(0, 20))
        fr = tk.Frame(self.content, bg=config.COLOR_CARD, padx=25, pady=25, highlightthickness=1, highlightbackground=config.COLOR_BORDER, bd=0); fr.pack(padx=20, fill="x")
        tk.Label(fr, text=config.t("user_lbl"), bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 5))
        self.u = tk.Entry(fr, bg="#0f0018", fg="white", bd=0, insertbackground="white", justify="center", font=("Consolas", 11)); self.u.pack(fill="x", ipady=5)
        tk.Frame(fr, bg=config.COLOR_BORDER, height=1).pack(fill="x", pady=(0, 15))
        tk.Label(fr, text=config.t("pass_lbl"), bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 5))
        self.p = tk.Entry(fr, show="*", bg="#0f0018", fg="white", bd=0, insertbackground="white", justify="center", font=("Consolas", 11)); self.p.pack(fill="x", ipady=5)
        tk.Frame(fr, bg=config.COLOR_BORDER, height=1).pack(fill="x", pady=(0, 20))
        BotonDinamico(self.content, config.COLOR_ACCENT, text=config.t("btn_login"), command=self.validar, width=25).pack(pady=(10, 5))
        BotonDinamico(self.content, "#69f0ae", text=config.t("btn_redeem"), command=self.abrir_registro, width=25).pack(pady=5)
        BotonDinamico(self.content, config.COLOR_DANGER, text=config.t("btn_exit"), command=sys.exit, width=25).pack(pady=10)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def abrir_registro(self):
        VentanaRegistro(self.controller)

    def validar(self):
        user = self.u.get()[:20]; pwd = self.p.get()
        try:
            resp = requests.post(f"{config.API_URL}/login", data={"username": user, "password": pwd})
            if resp.status_code == 200:
                data = resp.json()
                config.SESSION_TOKEN = data["access_token"]
                config.USER_ROLE = data["role"]
                config.USER_NAME = user
                config.USER_MEMBERSHIP = data["membresia"]
                try:
                    user_resp = requests.get(f"{config.API_URL}/users", headers=utils.get_auth_headers(), timeout=5)
                    if user_resp.status_code == 200:
                        my_user = next((u for u in user_resp.json() if u['username'] == user), None)
                        config.USER_EXPIRY = my_user['vencimiento'] if my_user and my_user.get('vencimiento') else "LIFETIME"
                    else: config.USER_EXPIRY = "LIFETIME"
                except: config.USER_EXPIRY = "LIFETIME"
                self.controller.switch_frame(MenuFrame)
            else: show_error("Error", "Invalid credentials.")
        except: show_error("Error", "Connection Failed.")

class MenuFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0); self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, config.COLOR_ACCENT)
        archivo_logo = utils.resource_path("Scanneler.png")

        try: 
            from PIL import Image, ImageTk
            self.pir = Image.open(archivo_logo)
            self.bgi = self.canvas.create_image(0, 0, anchor="nw")
            self.canvas.bind("<Configure>", self.rs)
        except Exception as e: 
            print(f"Error menu img: {e}")
            self.canvas.create_text(450, 200, text="SCANNELER", fill=config.COLOR_ACCENT, font=("Consolas", 50, "bold"))
            
        self.b_admin = BotonCanvas(self.canvas, 0, 0, 200, 50, config.t("menu_admin"), config.COLOR_ACCENT, self.go_admin) if config.USER_ROLE == 'admin' else None
        self.b_user = BotonCanvas(self.canvas, 0, 0, 200, 50, config.t("menu_user"), config.COLOR_USER, self.go_user)
        self.b_settings = BotonCanvas(self.canvas, 0, 0, 200, 50, config.t("menu_settings"), "#00e5ff", self.go_settings)
        self.b_exit = BotonCanvas(self.canvas, 0, 0, 200, 50, config.t("btn_exit"), config.COLOR_DANGER, sys.exit)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def rs(self, e):
        w, h = e.width, e.height
        cx = w / 2
        if hasattr(self, 'pir'):
            try: 
                from PIL import ImageTk, Image
                self.cbg = ImageTk.PhotoImage(self.pir.resize((w, h), Image.Resampling.LANCZOS))
                self.canvas.itemconfig(self.bgi, image=self.cbg)
            except: pass
        base_y = int(h * 0.75)
        if self.b_admin:
            self.b_admin.move_to(cx, base_y - 70)
            self.b_user.move_to(cx - 110, base_y)
            self.b_settings.move_to(cx + 110, base_y)
            self.b_exit.move_to(cx, base_y + 70)
        else:
            self.b_user.move_to(cx - 110, base_y)
            self.b_settings.move_to(cx + 110, base_y)
            self.b_exit.move_to(cx, base_y + 70)

    def go_admin(self): self.controller.switch_frame(AdminFrame)
    def go_user(self): self.controller.switch_frame(UserConfigFrame)
    def go_settings(self): self.controller.switch_frame(SettingsFrame)

class SettingsFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, "#00e5ff")
        self.content = tk.Frame(self.canvas, bg=config.COLOR_BG)
        self.wid = self.canvas.create_window(450, 350, window=self.content, anchor="center")
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))
        
        tk.Label(self.content, text=config.t("settings_title"), font=("Consolas", 18, "bold"), bg=config.COLOR_BG, fg="#00e5ff").pack(pady=(0, 40))
        tk.Label(self.content, text=config.t("lang_lbl"), font=("Consolas", 11, "bold"), bg=config.COLOR_BG, fg=config.COLOR_TEXT).pack(pady=(0, 20))
        btn_frame = tk.Frame(self.content, bg=config.COLOR_BG)
        btn_frame.pack(pady=10)
        self.btn_es = BotonDinamico(btn_frame, config.COLOR_ACCENT, text="ESPAÑOL (AR)", command=lambda: self.set_lang("es"), width=20)
        self.btn_es.pack(side="left", padx=15)
        if config.CURRENT_LANGUAGE == "es": self.btn_es.config(bg=config.COLOR_HOVER_BG, state="disabled") 
        self.btn_en = BotonDinamico(btn_frame, config.COLOR_ACCENT, text="ENGLISH (US)", command=lambda: self.set_lang("en"), width=20)
        self.btn_en.pack(side="left", padx=15)
        if config.CURRENT_LANGUAGE == "en": self.btn_en.config(bg=config.COLOR_HOVER_BG, state="disabled")
        BotonDinamico(self.content, config.COLOR_DANGER, text=config.t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), width=25).pack(pady=50)

    def set_lang(self, lang_code):
        config.CURRENT_LANGUAGE = lang_code
        self.controller.switch_frame(SettingsFrame)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

class AdminFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.canvas_bg = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0); self.canvas_bg.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas_bg, config.COLOR_ACCENT)
        style = ttk.Style()
        style.configure("TNotebook", background=config.COLOR_BG, borderwidth=0)
        self.nb = ttk.Notebook(self); self.tab_users = tk.Frame(self.nb, bg=config.COLOR_BG); self.tab_keys = tk.Frame(self.nb, bg=config.COLOR_BG)
        self.nb.add(self.tab_users, text="    USER DATABASE    "); self.nb.add(self.tab_keys, text="    LICENSE GENERATOR    ")
        self.nb_win = self.canvas_bg.create_window(450, 300, window=self.nb, width=1000, height=500)
        self.setup_tab_usuarios(); self.setup_tab_keys()
        self.btn_back = BotonDinamico(self, "#7c4dff", text="BACK TO MENU", command=lambda: controller.switch_frame(MenuFrame), width=20)
        self.back_win = self.canvas_bg.create_window(450, 650, window=self.btn_back)
        self.bind("<Configure>", self.reajustar)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def reajustar(self, e):
        w, h = e.width, e.height; cx = w/2
        self.canvas_bg.coords(self.nb_win, cx, h/2 - 30)
        self.canvas_bg.itemconfig(self.nb_win, width=w-100, height=h-150)
        self.canvas_bg.coords(self.back_win, cx, h - 50)

    def setup_tab_usuarios(self):
        self.form_container = tk.Frame(self.tab_users, bg=config.COLOR_BG, pady=5); self.form_container.pack(fill="x", padx=20)
        edit_fr = tk.LabelFrame(self.form_container, text=" ACCOUNT CONTROLS ", bg=config.COLOR_BG, fg=config.COLOR_TEXT, bd=1, highlightbackground=config.COLOR_BORDER); edit_fr.pack(fill="x", padx=5, pady=5)
        tk.Label(edit_fr, text="USER:", bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9)).grid(row=0, column=0, padx=5, pady=10)
        self.entry_u = tk.Entry(edit_fr, bg="#0f0018", fg="white", width=14, bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER); self.entry_u.grid(row=0, column=1, padx=5)
        tk.Label(edit_fr, text="PASS:", bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9)).grid(row=0, column=2, padx=5)
        self.entry_p = tk.Entry(edit_fr, show="*", bg="#0f0018", fg="white", width=14, bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER); self.entry_p.grid(row=0, column=3, padx=5)
        tk.Label(edit_fr, text="PLAN:", bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9)).grid(row=0, column=4, padx=5)
        self.m_v = ttk.Combobox(edit_fr, values=["Basic", "Medium", "Full"], state="readonly", width=10); self.m_v.set("Basic"); self.m_v.grid(row=0, column=5, padx=5)
        tk.Label(edit_fr, text="DUR:", bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9)).grid(row=0, column=6, padx=5)
        self.d_v = ttk.Combobox(edit_fr, values=["Weekly", "Monthly", "Yearly"], state="readonly", width=10); self.d_v.set("Monthly"); self.d_v.grid(row=0, column=7, padx=5)
        BotonDinamico(edit_fr, config.COLOR_ACCENT, text="UPDATE", command=self.actualizar_usuario, width=10, pady=2).grid(row=0, column=8, padx=10)
        list_container = tk.Frame(self.tab_users, bg=config.COLOR_BG); list_container.pack(fill="both", expand=True, padx=20, pady=5)
        self.list_canvas = tk.Canvas(list_container, bg=config.COLOR_BG, highlightthickness=0)
        self.list_scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.list_canvas.yview)
        self.list_frame = tk.Frame(self.list_canvas, bg=config.COLOR_BG)
        self.list_frame.bind("<Configure>", lambda e: self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all")))
        self.list_canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.list_canvas.configure(yscrollcommand=self.list_scrollbar.set)
        self.list_canvas.pack(side="left", fill="both", expand=True); self.list_scrollbar.pack(side="right", fill="y")
        self.actualizar_lista()

    def setup_tab_keys(self):
        container = tk.Frame(self.tab_keys, bg=config.COLOR_BG); container.pack(fill="both", expand=True, padx=80, pady=20)
        tk.Label(container, text="LICENSE GENERATOR SERVICE", font=("Consolas", 16, "bold"), bg=config.COLOR_BG, fg=config.COLOR_ACCENT).pack(pady=(0, 15))
        fk = tk.Frame(container, bg=config.COLOR_CARD, padx=20, pady=20, highlightthickness=1, highlightbackground=config.COLOR_BORDER); fk.pack(fill="x")
        tk.Label(fk, text="PLAN:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=0, padx=5, sticky="w")
        self.key_memb = ttk.Combobox(fk, values=["Basic", "Medium", "Full"], state="readonly", width=15); self.key_memb.set("Full"); self.key_memb.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(fk, text="DUR:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=2, padx=5, sticky="w")
        self.key_dur_type = ttk.Combobox(fk, values=["Weekly", "Monthly", "Yearly"], state="readonly", width=15); self.key_dur_type.set("Monthly"); self.key_dur_type.grid(row=0, column=3, padx=5, pady=5)
        tk.Label(fk, text="QTY:", bg=config.COLOR_CARD, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).grid(row=0, column=4, padx=5, sticky="w")
        self.key_qty = tk.Entry(fk, bg="#0f0018", fg="white", bd=0, width=8, highlightthickness=1, highlightbackground=config.COLOR_BORDER, justify="center"); self.key_qty.insert(0, "1"); self.key_qty.grid(row=0, column=5, padx=5, pady=5)
        BotonDinamico(container, config.COLOR_ACCENT, text="GENERATE NEW KEYS", command=self.solicitar_generar_keys, width=30).pack(pady=15)
        tk.Label(container, text="LATEST GENERATED KEY:", bg=config.COLOR_BG, fg=config.COLOR_ACCENT, font=("Consolas", 9, "bold")).pack(anchor="w")
        self.entry_result_quick = tk.Entry(container, bg="#1a0526", fg=config.COLOR_SUCCESS, font=("Consolas", 14, "bold"), bd=0, highlightthickness=1, highlightbackground=config.COLOR_SUCCESS, justify="center"); self.entry_result_quick.pack(fill="x", pady=(5, 15), ipady=8)
        tk.Label(container, text="FULL BATCH LOG:", bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9)).pack(anchor="w")
        self.txt_keys_output = tk.Text(container, bg="#000", fg="white", font=("Consolas", 10), height=6, bd=0, padx=10, pady=10); self.txt_keys_output.pack(fill="x")

    def solicitar_generar_keys(self):
        self.txt_keys_output.delete("1.0", tk.END); self.entry_result_quick.delete(0, tk.END)
        self.txt_keys_output.insert(tk.END, "> Fetching from database..."); self.update_idletasks()
        try:
            m = self.key_memb.get(); d_text = self.key_dur_type.get(); q_str = self.key_qty.get()
            if not q_str.isdigit(): return
            days = self.get_days_from_duration(d_text)
            resp = requests.post(f"{config.API_URL}/keys/generate", json={"membresia": m, "duracion_dias": days, "cantidad": int(q_str)}, headers=utils.get_auth_headers(), timeout=15)
            if resp.status_code == 201:
                data = resp.json(); keys = data.get("keys", []) or data.get("generated_keys", [])
                if keys:
                    self.entry_result_quick.insert(0, str(keys[0])); self.txt_keys_output.delete("1.0", tk.END)
                    self.txt_keys_output.insert(tk.END, f"--- {len(keys)} KEYS GENERATED ---\n\n"); self.txt_keys_output.insert(tk.END, "\n".join(keys))
                    show_info("Success", f"{len(keys)} Keys generated.")
                else: self.txt_keys_output.insert(tk.END, "\n[!] Empty response from server.")
            else: self.txt_keys_output.insert(tk.END, f"\n[!] Error {resp.status_code}: {resp.text}")
        except Exception as e: self.txt_keys_output.insert(tk.END, f"\n[!] Connection failed: {str(e)}")

    def get_days_from_duration(self, duration):
        mapping = {"Weekly": 7, "Monthly": 30, "Yearly": 365}; return mapping.get(duration, 30)

    def actualizar_lista(self):
        for widget in self.list_frame.winfo_children(): widget.destroy()
        header = tk.Frame(self.list_frame, bg="#1a0526", pady=5); header.pack(fill="x", pady=(0, 5))
        tk.Label(header, text="USERNAME", width=25, anchor="w", bg="#1a0526", fg=config.COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="left", padx=10)
        tk.Label(header, text="MEMBERSHIP", width=20, anchor="w", bg="#1a0526", fg=config.COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="left")
        tk.Label(header, text="ACTIONS", anchor="e", bg="#1a0526", fg=config.COLOR_ACCENT, font=("Consolas", 10, "bold")).pack(side="right", padx=120)
        try:
            r = requests.get(f"{config.API_URL}/users", headers=utils.get_auth_headers(), timeout=10)
            if r.status_code == 200:
                for u in r.json():
                    row = tk.Frame(self.list_frame, bg=config.COLOR_CARD, pady=5, padx=15, highlightthickness=1, highlightbackground="#2a0a38"); row.pack(fill="x", pady=1)
                    tk.Label(row, text=u['username'].upper(), width=25, anchor="w", bg=config.COLOR_CARD, fg=config.COLOR_TEXT).pack(side="left")
                    tk.Label(row, text=u['membresia'], width=20, anchor="w", bg=config.COLOR_CARD, fg=config.COLOR_USER).pack(side="left")
                    btn_box = tk.Frame(row, bg=config.COLOR_CARD); btn_box.pack(side="right")
                    BotonDinamico(btn_box, config.COLOR_ACCENT, text="EDIT", command=lambda un=u['username'], mb=u['membresia']: self.cargar_para_editar(un, mb), width=6, pady=2).pack(side="left", padx=2)
                    if u['username'] != "Jeler33": BotonDinamico(btn_box, config.COLOR_DANGER, text="DEL", command=lambda n=u['username']: self.borrar_cuenta(n), width=6, pady=2).pack(side="left", padx=2)
        except: pass

    def cargar_para_editar(self, u, m):
        self.entry_u.delete(0, tk.END); self.entry_u.insert(0, u); self.m_v.set(m); self.entry_p.delete(0, tk.END)

    def actualizar_usuario(self):
        u = self.entry_u.get(); m = self.m_v.get(); d_text = self.d_v.get()
        if not u: return
        try:
            days = self.get_days_from_duration(d_text)
            r = requests.put(f"{config.API_URL}/users/{u}", json={"membresia": m, "duracion_dias": days}, headers=utils.get_auth_headers())
            if r.status_code == 200: show_info("Success", f"Agent {u} updated."); self.actualizar_lista()
        except: pass

    def borrar_cuenta(self, n):
        if ask_yes_no("Security", f"Erase agent {n}?"):
            try:
                r = requests.delete(f"{config.API_URL}/users/{n}", headers=utils.get_auth_headers()); 
                if r.status_code == 200: self.actualizar_lista()
            except: pass

class UserConfigFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=config.COLOR_BG)
        self.controller = controller
        self.ui_map = {}
        self.rutas_seleccionadas = config.HISTORIAL_RUTAS.copy()
        
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scroll_content = tk.Frame(self.canvas, bg=config.COLOR_BG)
        self.anim = CyberRain(self.canvas, config.COLOR_ACCENT)
        self.cw = self.canvas.create_window((0, 0), window=self.scroll_content, anchor="n")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", lambda e: (self.canvas.coords(self.cw, e.width/2, 0), self.canvas.itemconfig(self.cw, width=min(e.width, 780))))
        self.scroll_content.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        tk.Label(self.scroll_content, text=f"{config.t('welcome')} {config.USER_NAME.upper()} [{config.USER_MEMBERSHIP.upper()}]", font=("Consolas", 18, "bold"), bg=config.COLOR_BG, fg=config.COLOR_ACCENT).pack(pady=20)
        fr = tk.LabelFrame(self.scroll_content, text=config.t("scan_config"), bg=config.COLOR_BG, fg=config.COLOR_TEXT, font=("Consolas", 10), bd=1, highlightbackground=config.COLOR_BORDER, highlightthickness=1, padx=15, pady=10)
        fr.pack(fill="x", padx=30, pady=10)
        
        row1 = tk.Frame(fr, bg=config.COLOR_BG); row1.pack(fill="x", pady=5)
        tk.Label(row1, text=config.t("path_lbl"), bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.pv = tk.StringVar(value=self.rutas_seleccionadas['path']); tk.Entry(row1, textvariable=self.pv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row1, config.COLOR_ACCENT, text=config.t("btn_select"), command=self.select_path, width=12, bg=config.COLOR_BG).pack(side="right")
        
        row2 = tk.Frame(fr, bg=config.COLOR_BG); row2.pack(fill="x", pady=5)
        tk.Label(row2, text=config.t("folder_lbl"), bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.fv = tk.StringVar(value=self.rutas_seleccionadas['folder']); tk.Entry(row2, textvariable=self.fv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1)
        
        row3 = tk.Frame(fr, bg=config.COLOR_BG); row3.pack(fill="x", pady=10)
        tk.Label(row3, text=config.t("list_lbl"), bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9), width=15, anchor="w").pack(side="left")
        self.lv = tk.StringVar(value=self.rutas_seleccionadas['list_path']); tk.Entry(row3, textvariable=self.lv, bg="#120026", fg="white", bd=0, highlightthickness=1, highlightbackground=config.COLOR_BORDER).pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row3, config.COLOR_SUCCESS, text=config.t("btn_browse"), command=self.select_list, width=12, bg=config.COLOR_BG).pack(side="right")

        row4 = tk.Frame(fr, bg=config.COLOR_BG); row4.pack(fill="x", pady=5)
        tk.Label(row4, text=config.t("target_lbl"), bg=config.COLOR_BG, fg="#00e5ff", font=("Consolas", 9, "bold"), width=15, anchor="w").pack(side="left")
        self.tv = tk.StringVar(); tk.Entry(row4, textvariable=self.tv, bg="#120026", fg="#00e5ff", bd=0, highlightthickness=1, highlightbackground="#00e5ff").pack(side="left", fill="x", expand=True, ipady=1, padx=(0, 5))
        BotonDinamico(row4, "#00e5ff", text=config.t("btn_pick"), command=self.select_target, width=12, bg=config.COLOR_BG).pack(side="right")
        
        ob = tk.Frame(self.scroll_content, bg=config.COLOR_BG, pady=20); ob.pack(fill="x", padx=40)
        tk.Label(self.scroll_content, text=f"EXPIRES: {config.USER_EXPIRY}", font=("Consolas", 11, "bold"), bg=config.COLOR_BG, fg=config.COLOR_SUCCESS).pack(in_=ob, side="bottom", pady=10)
        
        perms = {'Basic': ['f1','f2','f3','f5','f7','f18','f20'], 'Medium': ['f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f18','f20','vt'], 'Full': ['f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12','f13','f14','f15','f16','f17','f18','f19','f20','f21','f22','f23','f24','f25','f26', 'vt']}
        self.alwd = perms.get(config.USER_MEMBERSHIP, ['f1','f2','f3','f5','f7','f18','f20'])
        
        ctrl_fr = tk.Frame(ob, bg=config.COLOR_BG); ctrl_fr.pack(fill="x", pady=(0, 10))
        tk.Label(ctrl_fr, text=config.t("modules_lbl"), bg=config.COLOR_BG, fg=config.COLOR_USER, font=("Consolas", 9, "bold")).pack(side="left")
        tk.Button(ctrl_fr, text=config.t("sel_all"), command=lambda: self.toggle_all(True), bg=config.COLOR_BG, fg=config.COLOR_SUCCESS, bd=0, font=("Consolas", 8, "bold"), cursor="hand2", activebackground=config.COLOR_BG, activeforeground="white").pack(side="right")
        tk.Button(ctrl_fr, text=config.t("desel_all"), command=lambda: self.toggle_all(False), bg=config.COLOR_BG, fg=config.COLOR_DANGER, bd=0, font=("Consolas", 8, "bold"), cursor="hand2", activebackground=config.COLOR_BG, activeforeground="white").pack(side="right", padx=10)
        
        opts = [("Fase 1: ShimCache Analysis", 'f1'), ("Fase 2: AppCompat Store", 'f2'), ("Fase 3: Identity Verification", 'f3'), ("Fase 4: Digital Signatures", 'f4'), ("Fase 5: Keyword Search", 'f5'), ("Fase 6: Hidden Files Scan", 'f6'), ("Fase 7: MFT & ADS Scan", 'f7'), ("Fase 8: UserAssist (ROT13)", 'f8'), ("Fase 9: USB Device History", 'f9'), ("Fase 10: DNS and Discord Cache", 'f10'), ("Fase 11: Browser Forensics", 'f11'), ("Fase 12: Persistence", 'f12'), ("Fase 13: Windows Event Logs", 'f13'), ("Fase 14: RAM Process Hunter", 'f14'), ("Fase 15: Game Cheat Hunter (Deep)", 'f15'), ("Fase 16: Nuclear Traces (BAM/Pipes)", 'f16'), ("Fase 17: Kernel Hunter (Drivers)", 'f17'), ("Fase 18: DNA & Prefetch (Forensic)", 'f18'), ("Fase 19: Network Deep Inspection", 'f19'), ("Fase 20: Toxic LNK & Module Hunter", 'f20'), ("Fase 21: Ghost Trails (Registry MRU)", 'f21'), ("Fase 22: Memory Injection Hunter (Elite)", 'f22'), ("Fase 23: Rogue Driver Hunter (Kernel)", 'f23'),("Fase 24: Deep Static Heuristics (Hidden Files)", 'f24'), ("Fase 25: Metamorphosis Hunter (Hot-Swap)", 'f25'), ("F26: String Cleaner", 'f26'),("Cloud: VirusTotal API", 'vt')]
        for text, key in opts:
            r = tk.Frame(ob, bg=config.COLOR_CARD, pady=12, padx=15, highlightthickness=1, highlightbackground=config.COLOR_BORDER, bd=0)
            r.pack(fill="x", pady=6)
            is_enabled = key in self.alwd
            var_active = tk.BooleanVar(value=is_enabled)
            cb = tk.Checkbutton(r, text=text, variable=var_active, state="normal" if is_enabled else "disabled", bg=config.COLOR_CARD, fg=config.COLOR_TEXT if is_enabled else "#333", selectcolor=config.COLOR_BG, activebackground=config.COLOR_CARD, activeforeground=config.COLOR_ACCENT, font=("Consolas", 11)); cb.pack(side="left")
            var_modo = tk.StringVar(value="Usar Lista")
            if is_enabled:
                if key == 'vt' or key == 'f5': tk.Label(r, text=config.t("only_list"), bg=config.COLOR_CARD, fg="#b39ddb", font=("Consolas", 9, "italic")).pack(side="right", padx=25)
                else: selector = ttk.Combobox(r, textvariable=var_modo, values=["Usar Lista", "Analizar Todo"], state="readonly", width=15); selector.pack(side="right", padx=25)
            elif not is_enabled: tk.Label(r, text=config.t("upgrade"), bg=config.COLOR_CARD, fg=config.COLOR_DANGER, font=("Consolas", 9, "bold")).pack(side="right", padx=25)
            self.ui_map[key] = {'active': var_active, 'modo': var_modo}
        
        fb = tk.Frame(self.scroll_content, bg=config.COLOR_BG); fb.pack(pady=40)
        BotonDinamico(fb, config.COLOR_ACCENT, text=config.t("btn_start"), command=self.go, width=25).pack(side="left", padx=15)
        BotonDinamico(fb, "#7c4dff", text=config.t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), width=25).pack(side="left", padx=15)
        BotonDinamico(fb, config.COLOR_DANGER, text=config.t("btn_exit"), command=sys.exit, width=25).pack(side="left", padx=15)

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def toggle_all(self, state):
        for k, v in self.ui_map.items():
            if k in self.alwd: v['active'].set(state)

    def select_path(self):
        p = filedialog.askdirectory()
        if p: self.pv.set(p); config.HISTORIAL_RUTAS['path'] = p

    def select_list(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f: self.lv.set(f); config.HISTORIAL_RUTAS['list_path'] = f

    def select_target(self):
        f = filedialog.askopenfilename(title="Select Suspicious File (Phase 25)", filetypes=[("Executables", "*.exe"), ("All files", "*.*")])
        if f: self.tv.set(f)

    def go(self):
        try:
            config.HISTORIAL_RUTAS['path'] = self.pv.get()
            config.HISTORIAL_RUTAS['folder'] = self.fv.get()
            config.HISTORIAL_RUTAS['list_path'] = self.lv.get()
            config.HISTORIAL_RUTAS['target_file'] = self.tv.get()
            
            seleccion_modulos = {k: {'active': v['active'].get(), 'modo': v['modo'].get()} for k, v in self.ui_map.items()}
            pals = utils.cargar_palabras(config.HISTORIAL_RUTAS['list_path'])
            if pals or any(m['modo'] == 'Analizar Todo' for m in seleccion_modulos.values()):
                self.controller.switch_frame(ScannerFrame, pals, seleccion_modulos, config.HISTORIAL_RUTAS)
            else: show_error("Error", "List is empty and no 'Analizar Todo' selected.")
        except Exception as e: print(f"Error in go: {e}")

class ScannerFrame(tk.Frame):
    def __init__(self, parent, controller, palabras, configuracion, rutas_config):
        super().__init__(parent, bg=config.COLOR_BG)
        config.CANCELAR_ESCANEO = False
        self.controller = controller
        self.palabras = palabras
        self.config = configuracion
        self.rutas = rutas_config
        self.cola_estado = Queue()
        
        self.canvas = tk.Canvas(self, bg=config.COLOR_BG, highlightthickness=0); self.canvas.pack(fill="both", expand=True)
        self.anim = CyberRain(self.canvas, config.COLOR_ACCENT)
        self.content = tk.Frame(self.canvas, bg=config.COLOR_BG)
        self.wid = self.canvas.create_window(450, 300, window=self.content, anchor="center") 
        self.canvas.bind("<Configure>", lambda e: self.canvas.coords(self.wid, e.width/2, e.height/2))

        tk.Label(self.content, text=config.t("audit_prog"), font=("Consolas", 18, "bold"), bg=config.COLOR_BG, fg=config.COLOR_ACCENT).pack(pady=40)
        self.l_status = tk.Label(self.content, text=config.t("init"), font=("Consolas", 12), bg=config.COLOR_BG, fg=config.COLOR_TEXT); self.l_status.pack(pady=30)
        BotonDinamico(self.content, config.COLOR_DANGER, text=config.t("stop_scan"), command=self.stop, width=25).pack()
        
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
        
        self.check_queue()

    def cleanup(self):
        if hasattr(self, 'anim'): self.anim.detener()

    def check_queue(self):
        try:
            while not self.cola_estado.empty():
                msg = self.cola_estado.get_nowait()
                if msg == "DONE_SIGNAL": self.finish_scan_gui()
                else: self.l_status.config(text=msg)
        except: pass
        if not config.CANCELAR_ESCANEO: self.after(100, self.check_queue)

    def update_status(self, msg): self.cola_estado.put(msg)
    
    def stop(self):
        config.CANCELAR_ESCANEO = True
        self.controller.switch_frame(MenuFrame)

    def finish_scan_gui(self):
        self.anim.detener()
        show_info("DONE", f"Results saved in:\n{self.fp_final}")
        self.controller.switch_frame(MenuFrame)

    def run_scan(self):
        bd, fn = self.rutas.get('path', os.path.abspath(".")), self.rutas.get('folder', "Resultados_SS")
        fp = os.path.join(bd, fn)
        if not os.path.exists(fp): os.makedirs(fp, exist_ok=True)
        
        # Asignar rutas globales en config
        config.reporte_shim = os.path.join(fp, "Shimcache_Rastros.txt")
        config.reporte_appcompat = os.path.join(fp, "rastro_appcompat.txt")
        config.reporte_path = os.path.join(fp, "buscar_en_disco.txt")
        config.reporte_sospechosos = os.path.join(fp, "cambios_sospechosos.txt")
        config.reporte_firmas = os.path.join(fp, "Digital_Signatures_ZeroTrust.txt")
        config.reporte_ocultos = os.path.join(fp, "archivos_ocultos.txt")
        config.reporte_mft = os.path.join(fp, "MFT_Archivos.txt")
        config.reporte_vt = os.path.join(fp, "detecciones_virustotal.txt")
        config.reporte_userassist = os.path.join(fp, "UserAssist_Decoded.txt")
        config.reporte_usb = os.path.join(fp, "USB_History.txt")
        config.reporte_dns = os.path.join(fp, "DNS_Cache.txt")
        config.reporte_browser = os.path.join(fp, "Browser_Forensics.txt")
        config.reporte_persistencia = os.path.join(fp, "Persistence_Check.txt")
        config.reporte_eventos = os.path.join(fp, "Windows_Events.txt")
        config.reporte_process = os.path.join(fp, "Process_Hunter.txt")
        config.reporte_game = os.path.join(fp, "Game_Cheat_Hunter.txt")
        config.reporte_nuclear = os.path.join(fp, "Nuclear_Traces.txt")
        config.reporte_kernel = os.path.join(fp, "Kernel_Anomalies.txt")
        config.reporte_dna = os.path.join(fp, "DNA_Prefetch.txt")
        config.reporte_network = os.path.join(fp, "Network_Anomalies.txt")
        config.reporte_toxic = os.path.join(fp, "Toxic_LNK.txt")
        config.reporte_ghost = os.path.join(fp, "Ghost_Trails.txt")
        config.reporte_memory = os.path.join(fp, "Memory_Injection_Report.txt")
        config.reporte_drivers = os.path.join(fp, "Rogue_Drivers.txt")
        config.reporte_static = os.path.join(fp, "Deep_Static_Analysis.txt")
        config.reporte_morph = os.path.join(fp, "Metamorphosis_Report.txt")
        config.reporte_cleaning = os.path.join(fp, "String_Cleaner_Detection.txt")

        try: scanner_engine.generar_reporte_html(fp, self.config)
        except: pass
        
        vte = self.config.get('vt', {}).get('active', False)
        if vte: 
            with open(config.reporte_vt, "w", encoding="utf-8") as f: f.write(f"=== VT: {datetime.datetime.now()} ===\n\n")
            threading.Thread(target=scanner_engine.worker_virustotal, daemon=True).start()
        
        fases = [
            ('f1', scanner_engine.fase_shimcache), ('f2', scanner_engine.fase_rastro_appcompat), ('f3', scanner_engine.fase_nombre_original),
            ('f4', scanner_engine.fase_verificar_firmas), ('f5', scanner_engine.fase_buscar_en_disco), ('f6', scanner_engine.fase_archivos_ocultos),
            ('f7', scanner_engine.fase_mft_ads), ('f8', scanner_engine.fase_userassist), ('f9', scanner_engine.fase_usb_history),
            ('f10', scanner_engine.fase_dns_cache), ('f11', scanner_engine.fase_browser_forensics), ('f12', scanner_engine.fase_persistence),
            ('f13', scanner_engine.fase_event_logs), ('f14', scanner_engine.fase_process_hunter), ('f15', scanner_engine.fase_game_cheat_hunter),
            ('f16', scanner_engine.fase_nuclear_traces), ('f17', scanner_engine.fase_kernel_hunter), ('f18', scanner_engine.fase_dna_prefetch),
            ('f19', scanner_engine.fase_network_hunter), ('f20', scanner_engine.fase_toxic_lnk), ('f21', scanner_engine.fase_ghost_trails),
            ('f22', scanner_engine.fase_memory_anomaly), ('f23', scanner_engine.fase_rogue_drivers), ('f24', scanner_engine.fase_deep_static),
            ('f25', scanner_engine.fase_metamorphosis_hunter), ('f26', scanner_engine.fase_string_cleaning)
        ]
        
        for k, func in fases:
            if config.CANCELAR_ESCANEO: break
            if self.config.get(k, {}).get('active'):
                self.update_status(f"Running: {k.upper()}...")
                
                args = []
                if k == 'f3': args = [vte, self.palabras, self.config[k]['modo']]
                elif k == 'f4': args = [self.palabras, vte, self.config[k]['modo']]
                elif k == 'f5': args = [self.palabras]
                elif k == 'f24': args = [self.palabras, self.config[k]['modo']]
                elif k == 'f25': args = [self.palabras, self.config[k]['modo'], config.HISTORIAL_RUTAS.get('target_file')]
                else: args = [self.palabras, self.config[k]['modo']]
                
                try: func(*args)
                except Exception as e: print(f"Error executing {k}: {e}") 
                
                try: scanner_engine.generar_reporte_html(fp, self.config)
                except: pass
        
        scanner_engine.cola_vt.put(None)
        if vte:
            self.update_status("Finalizando subidas a VirusTotal...")
            scanner_engine.cola_vt.join()

        if not config.CANCELAR_ESCANEO: 
            self.fp_final = fp
            self.cola_estado.put("DONE_SIGNAL")