import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import sys
import os
import requests
import datetime
import random
import time
from queue import Queue
from PIL import Image, ImageTk

# Importaciones locales
import config
import utils
import scanner_engine

# --- CONFIGURACIÓN GLOBAL ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# Colores (Seguros)
COLOR_BG = getattr(config, 'COLOR_BG', "#020005")
COLOR_PANEL = getattr(config, 'COLOR_CARD', "#12001F")
COLOR_ACCENT = getattr(config, 'COLOR_ACCENT', "#D500F9")
COLOR_ACCENT_HOVER = getattr(config, 'COLOR_ACCENT_HOVER', "#A000C8")
COLOR_DANGER = getattr(config, 'COLOR_DANGER', "#FF0055")
COLOR_SUCCESS = getattr(config, 'COLOR_SUCCESS', "#00E676")
COLOR_TEXT = getattr(config, 'COLOR_TEXT', "#E0B0FF")
COLOR_BORDER = getattr(config, 'COLOR_BORDER', "#4A0072")

# =============================================================================
# 1. COMPONENTES VISUALES
# =============================================================================

class CyberRain(ctk.CTkCanvas):
    def __init__(self, master, color_accent, **kwargs):
        super().__init__(master, bg=COLOR_BG, highlightthickness=0, **kwargs)
        self.color = color_accent
        self.drops = []
        self.scanline_y = 0
        self.width = self.winfo_screenwidth()
        self.height = self.winfo_screenheight()
        self.is_running = True
        self.after_id = None
        
        self.crear_grid()
        self.crear_gotas()
        self.animar()
        
    def crear_grid(self):
        for x in range(0, self.width, 100):
            self.create_line(x, 0, x, self.height, fill="#0a0014", width=1)
        for y in range(0, self.height, 100):
            self.create_line(0, y, self.width, y, fill="#0a0014", width=1)

    def crear_gotas(self):
        try:
            for _ in range(50): 
                x = random.randint(0, self.width)
                y = random.randint(-500, self.height)
                speed = random.randint(3, 8)
                char = random.choice(["0", "1", "x", "FF", "A4", "Ω", "⚡"])
                c = self.color if random.random() > 0.7 else "#2a003b"
                tag = self.create_text(x, y, text=char, fill=c, font=("Consolas", 10), tag="rain")
                self.drops.append([tag, speed, y])
        except: pass
        
    def animar(self):
        if not self.is_running: return
        try:
            if not self.winfo_exists(): 
                self.is_running = False
                return
            h = 1500 
            for i in range(len(self.drops)):
                tag, speed, y = self.drops[i]
                y += speed
                if y > h: 
                    y = random.randint(-100, 0)
                    self.coords(tag, random.randint(0, self.width), y)
                else: 
                    self.move(tag, 0, speed)
                self.drops[i][2] = y
            
            self.delete("scanline")
            self.scanline_y += 4
            if self.scanline_y > self.height: self.scanline_y = -100
            self.create_line(0, self.scanline_y, self.width, self.scanline_y, 
                             fill=self.color, width=2, tag="scanline", stipple="gray25")
            
            self.after_id = self.after(30, self.animar)
        except: self.is_running = False
        
    def detener(self):
        self.is_running = False
        if self.after_id:
            try: self.after_cancel(self.after_id)
            except: pass
            self.after_id = None

class ModernCard(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, corner_radius=15, fg_color=COLOR_PANEL, border_width=1, border_color=COLOR_BORDER, **kwargs)
        self.scanner_bar = ctk.CTkFrame(self, height=2, fg_color=COLOR_ACCENT, corner_radius=0)
        self.scanner_bar.place(relx=0, rely=0, relwidth=1)
        self.scan_pos = 0.0
        self.border_colors = [COLOR_BORDER, "#6A0090", "#8A00B0", COLOR_ACCENT]
        self.color_idx = 0
        self.direction = 1
        self.animate_card()

    def animate_card(self):
        try:
            if not self.winfo_exists(): return
            self.scan_pos += 0.01
            if self.scan_pos > 1.3: self.scan_pos = -0.3
            
            if 0 <= self.scan_pos <= 1:
                self.scanner_bar.place(rely=self.scan_pos)
                self.scanner_bar.lift()
                self.scanner_bar.lower()
            else:
                self.scanner_bar.place_forget()

            if int(self.scan_pos * 100) % 5 == 0:
                self.configure(border_color=self.border_colors[self.color_idx])
                self.color_idx += self.direction
                if self.color_idx >= len(self.border_colors) - 1: self.direction = -1
                elif self.color_idx <= 0: self.direction = 1

            self.after(20, self.animate_card)
        except: pass

# =============================================================================
# 2. VENTANAS SECUNDARIAS
# =============================================================================

class VentanaRegistro(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("ACCESS REQUEST")
        self.geometry("420x600")
        self.configure(fg_color=COLOR_BG)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 420) // 2
        y = (self.winfo_screenheight() - 600) // 2
        self.geometry(f"+{x}+{y}")

        self.anim = CyberRain(self, COLOR_ACCENT)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()

        ctk.CTkLabel(self, text="[ NEW AGENT REGISTRATION ]", font=("Segoe UI", 18, "bold"), text_color=COLOR_SUCCESS).pack(pady=(40, 20))
        
        f = ModernCard(self)
        f.pack(fill="x", padx=30, pady=10)
        
        self.entry_key = ctk.CTkEntry(f, placeholder_text="LICENSE KEY (XXXX-XXXX)", justify="center", height=50, border_color="#444", fg_color="#080010")
        self.entry_key.pack(fill="x", pady=(20, 10), padx=20)
        
        self.entry_u = ctk.CTkEntry(f, placeholder_text="DESIRED USERNAME", justify="center", height=50, border_color="#444", fg_color="#080010")
        self.entry_u.pack(fill="x", pady=10, padx=20)
        
        self.entry_p = ctk.CTkEntry(f, placeholder_text="SECURE PASSWORD", show="•", justify="center", height=50, border_color="#444", fg_color="#080010")
        self.entry_p.pack(fill="x", pady=(10, 20), padx=20)
        
        ctk.CTkButton(self, text="INITIALIZE AGENT", command=self.enviar_registro, height=50, fg_color=COLOR_SUCCESS, hover_color="#00cc52", text_color="black", font=("Segoe UI", 12, "bold")).pack(pady=15, padx=30, fill="x")
        ctk.CTkButton(self, text="ABORT", command=self.destroy, height=40, fg_color="transparent", border_width=1, border_color=COLOR_DANGER, text_color=COLOR_DANGER, hover_color="#330000").pack(pady=5, padx=30, fill="x")

    def enviar_registro(self):
        k = self.entry_key.get().strip()
        u = self.entry_u.get().strip()
        p = self.entry_p.get().strip()
        if not k or not u or not p: return
        try:
            resp = requests.post(f"{config.API_URL}/keys/redeem", json={"key_code": k, "username": u, "password": p}, timeout=15)
            if resp.status_code == 201: 
                messagebox.showinfo("Success", "Agent registered successfully.")
                self.destroy()
            else: 
                messagebox.showerror("Access Denied", f"Error: {resp.json().get('detail', 'Invalid Key')}")
        except Exception: pass

class AdminFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        
        self.anim = CyberRain(self, COLOR_DANGER) 
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()

        ctk.CTkLabel(self, text=config.t("adm_title"), font=("Segoe UI", 24, "bold"), text_color="white").pack(pady=30)
        
        self.tab = ctk.CTkTabview(self, width=950, height=550, segmented_button_selected_color=COLOR_ACCENT, segmented_button_selected_hover_color=COLOR_ACCENT_HOVER, fg_color=COLOR_PANEL, text_color="white")
        self.tab.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        self.tab.add(config.t("tab_users"))
        self.tab.add(config.t("tab_licenses"))
        
        self.setup_users(self.tab.tab(config.t("tab_users")))
        self.setup_keys(self.tab.tab(config.t("tab_licenses")))
        
        ctk.CTkButton(self, text=config.t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), fg_color="transparent", border_width=1, border_color=COLOR_BORDER, hover_color="#220033", width=200).pack(pady=10)

    def cleanup(self): self.anim.detener()

    def get_days(self, duration_text):
        mapping = {"Weekly": 7, "Monthly": 30, "Yearly": 365, "Lifetime": 3650}
        return mapping.get(duration_text, 30)

    def setup_users(self, p):
        f = ctk.CTkFrame(p, fg_color="#1a002a", corner_radius=10)
        f.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(f, text=config.t("lbl_edit_user"), font=("Consolas", 10, "bold"), text_color=COLOR_ACCENT).pack(side="left", padx=10)
        self.u_e = ctk.CTkEntry(f, placeholder_text="Username", width=150, border_color="#444", fg_color="#0a0010")
        self.u_e.pack(side="left", padx=5, pady=10)
        
        self.m_c = ctk.CTkComboBox(f, values=["Basic", "Medium", "Full"], width=100, border_color="#444", button_color="#333", fg_color="#0a0010")
        self.m_c.set("Basic")
        self.m_c.pack(side="left", padx=5)
        
        self.d_c = ctk.CTkComboBox(f, values=["Weekly", "Monthly", "Yearly", "Lifetime"], width=100, border_color="#444", button_color="#333", fg_color="#0a0010")
        self.d_c.set("Monthly")
        self.d_c.pack(side="left", padx=5)
        
        ctk.CTkButton(f, text=config.t("btn_update"), command=self.upd_u, width=100, fg_color=COLOR_ACCENT, text_color="black", hover_color=COLOR_ACCENT_HOVER).pack(side="left", padx=10)
        ctk.CTkButton(f, text=config.t("btn_refresh"), command=self.ref_u, width=80, fg_color="transparent", border_width=1, border_color=COLOR_BORDER).pack(side="right", padx=10)
        
        self.lst = ctk.CTkScrollableFrame(p, label_text=config.t("lbl_db"), fg_color="transparent")
        self.lst.pack(fill="both", expand=True, padx=10, pady=5)
        self.ref_u()

    def setup_keys(self, p):
        center = ctk.CTkFrame(p, fg_color="transparent")
        center.pack(fill="both", expand=True, padx=50, pady=20)
        
        ctk.CTkLabel(center, text=config.t("lbl_gen_lic"), font=("Segoe UI", 16, "bold"), text_color=COLOR_SUCCESS).grid(row=0, column=0, columnspan=4, pady=(0, 20), sticky="w")
        
        ctk.CTkLabel(center, text=config.t("lbl_memb")).grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.k_m = ctk.CTkComboBox(center, values=["Basic", "Medium", "Full"], width=200, border_color="#444", fg_color="#0a0010")
        self.k_m.set("Full")
        self.k_m.grid(row=1, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(center, text=config.t("lbl_dur")).grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.k_d = ctk.CTkComboBox(center, values=["Weekly", "Monthly", "Yearly", "Lifetime"], width=200, border_color="#444", fg_color="#0a0010")
        self.k_d.set("Monthly")
        self.k_d.grid(row=2, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(center, text=config.t("lbl_qty")).grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.k_q = ctk.CTkEntry(center, width=200, border_color="#444", justify="center", fg_color="#0a0010")
        self.k_q.insert(0, "1")
        self.k_q.grid(row=3, column=1, padx=10, pady=10)
        
        ctk.CTkButton(center, text=config.t("btn_gen"), command=self.gen_k, fg_color=COLOR_SUCCESS, text_color="black", hover_color="#00cc52", height=40).grid(row=4, column=0, columnspan=2, pady=30, sticky="ew")
        
        ctk.CTkLabel(center, text=config.t("lbl_log"), text_color="gray", font=("Consolas", 10)).grid(row=0, column=2, sticky="w", padx=20)
        self.k_out = ctk.CTkTextbox(center, width=400, height=300, font=("Consolas", 11), fg_color="#0a0010", border_color="#333", border_width=1)
        self.k_out.grid(row=1, column=2, rowspan=5, padx=20, sticky="nsew")

    def ref_u(self):
        widgets = self.lst.winfo_children()
        for i in range(len(widgets)):
             if isinstance(widgets[i], ctk.CTkFrame) and widgets[i].winfo_height() > 30: widgets[i].destroy()

        try:
            r = requests.get(f"{config.API_URL}/users", headers=utils.get_auth_headers(), timeout=5)
            if r.status_code == 200:
                for u in r.json():
                    row = ctk.CTkFrame(self.lst, fg_color="#181818", corner_radius=5)
                    row.pack(fill="x", pady=2)
                    ctk.CTkLabel(row, text=u['username'].upper(), width=200, anchor="w", font=("Consolas", 11, "bold"), text_color="white").pack(side="left", padx=10)
                    memb_col = COLOR_ACCENT if u['membresia'] == "Full" else ("#ffaa00" if u['membresia'] == "Medium" else "#888")
                    ctk.CTkLabel(row, text=u['membresia'], width=100, anchor="w", text_color=memb_col, font=("Segoe UI", 10, "bold")).pack(side="left")
                    expiry = u.get('vencimiento', 'N/A')
                    ctk.CTkLabel(row, text=str(expiry), width=150, anchor="w", text_color="#666", font=("Consolas", 10)).pack(side="left")
                    if u['username'] != "Jeler33":
                        ctk.CTkButton(row, text="DELETE", width=60, height=25, fg_color=COLOR_DANGER, hover_color="#990000", command=lambda n=u['username']: self.del_u(n)).pack(side="right", padx=10, pady=5)
                        ctk.CTkButton(row, text="SELECT", width=60, height=25, fg_color="transparent", border_width=1, border_color=COLOR_BORDER, command=lambda n=u['username']: self.select_user(n)).pack(side="right")
        except: pass

    def select_user(self, name):
        self.u_e.delete(0, tk.END)
        self.u_e.insert(0, name)

    def upd_u(self): 
        user = self.u_e.get()
        if not user: return
        plan = self.m_c.get()
        days = self.get_days(self.d_c.get())
        try:
            requests.put(f"{config.API_URL}/users/{user}", json={"membresia": plan, "duracion_dias": days}, headers=utils.get_auth_headers())
            messagebox.showinfo("Updated", f"User {user} updated.")
            self.ref_u()
        except: messagebox.showerror("Error", "Update failed.")

    def del_u(self, n): 
        if messagebox.askyesno("Confirm", f"Delete user {n}?"):
            try:
                requests.delete(f"{config.API_URL}/users/{n}", headers=utils.get_auth_headers())
                self.ref_u()
            except: pass

    def gen_k(self):
        plan = self.k_m.get()
        days = self.get_days(self.k_d.get())
        try: qty = int(self.k_q.get())
        except: qty = 1
        self.k_out.insert("0.0", f"> Generating {qty} {plan} keys for {days} days...\n")
        self.update()
        try:
            r = requests.post(f"{config.API_URL}/keys/generate", json={"membresia": plan, "cantidad": qty, "duracion_dias": days}, headers=utils.get_auth_headers())
            if r.status_code == 201:
                keys = r.json().get("keys", []) or r.json().get("generated_keys", [])
                self.k_out.delete("0.0", "end")
                self.k_out.insert("0.0", "\n".join(keys))
            else: self.k_out.insert("0.0", f"[ERROR] API: {r.text}\n")
        except Exception as e: self.k_out.insert("0.0", f"[ERROR] Network: {e}\n")

# =============================================================================
# 3. APLICACIÓN PRINCIPAL (Carga y Login)
# =============================================================================

class CargaDinamicaFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        
        self.anim = CyberRain(self, COLOR_ACCENT)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        self.center_box = ctk.CTkFrame(self, fg_color="#0a0010", corner_radius=30, border_width=2, border_color=COLOR_BORDER)
        self.center_box.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.45, relheight=0.45)
        
        try:
            img_path = utils.resource_path("Scanneler.png")
            if os.path.exists(img_path):
                pil_img = Image.open(img_path)
                self.logo_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(120, 120))
                ctk.CTkLabel(self.center_box, image=self.logo_img, text="").pack(pady=(30, 10))
        except: pass

        ctk.CTkLabel(self.center_box, text="SCANNELER", font=("Segoe UI", 48, "bold"), text_color="white").pack(pady=(10, 5))
        ctk.CTkLabel(self.center_box, text="FORENSIC SYSTEM 2026", font=("Consolas", 14), text_color=COLOR_ACCENT, width=300).pack()
        
        self.pb = ctk.CTkProgressBar(self.center_box, width=350, height=6, progress_color=COLOR_ACCENT, border_color=COLOR_BORDER)
        self.pb.pack(pady=(40, 10))
        self.pb.set(0)
        
        self.loading_text = ctk.CTkLabel(self.center_box, text=config.t("init"), font=("Consolas", 10), text_color="gray")
        self.loading_text.pack(pady=(0, 20))
        
        self.after(500, self.iniciar_carga)

    def cleanup(self): self.anim.detener()

    def iniciar_carga(self):
        self.pb.set(0.3)
        self.loading_text.configure(text="LOADING NEURAL PATTERNS...")
        self.update()
        try: utils.inicializar_yara()
        except: pass
        self.pb.set(0.7)
        time.sleep(0.3)
        self.pb.set(1.0)
        self.loading_text.configure(text="SYSTEM READY.")
        self.after(600, lambda: self.controller.switch_frame(LoginFrame))

class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        
        self.anim = CyberRain(self, config.COLOR_USER if hasattr(config, 'COLOR_USER') else COLOR_ACCENT)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()
        
        card = ctk.CTkFrame(self, fg_color="#0a0010", corner_radius=25, border_width=2, border_color=COLOR_BORDER, width=450, height=550)
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False) 
        
        ctk.CTkLabel(card, text=config.t("login_title"), font=("Segoe UI", 32, "bold"), text_color="white").pack(pady=(50, 10))
        ctk.CTkLabel(card, text=config.t("login_sub"), font=("Consolas", 12), text_color=COLOR_ACCENT).pack(pady=(0, 40))
        
        self.u = ctk.CTkEntry(card, placeholder_text=config.t("user_ph"), width=320, height=50, font=("Segoe UI", 14), border_color=COLOR_BORDER, justify="center", fg_color="#1a002a")
        self.u.pack(pady=10)
        
        self.p = ctk.CTkEntry(card, placeholder_text=config.t("pass_ph"), show="•", width=320, height=50, font=("Segoe UI", 14), border_color=COLOR_BORDER, justify="center", fg_color="#1a002a")
        self.p.pack(pady=10)
        
        ctk.CTkButton(card, text=config.t("btn_connect"), command=self.validar, width=320, height=50, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color="black", font=("Segoe UI", 13, "bold")).pack(pady=(30, 20))
        
        btns_frame = ctk.CTkFrame(card, fg_color="transparent")
        btns_frame.pack(pady=10)
        
        ctk.CTkButton(btns_frame, text=config.t("btn_redeem"), command=self.abrir_registro, width=150, height=35, fg_color="transparent", border_width=1, border_color=COLOR_BORDER, text_color="#aaa", hover_color="#220033").pack(side="left", padx=5)
        ctk.CTkButton(btns_frame, text=config.t("btn_exit"), command=sys.exit, width=150, height=35, fg_color="transparent", text_color=COLOR_DANGER, hover_color="#220000").pack(side="right", padx=5)

    def cleanup(self): self.anim.detener()
    def abrir_registro(self): VentanaRegistro(self.controller)

    def validar(self):
        user = self.u.get(); pwd = self.p.get()
        try:
            resp = requests.post(f"{config.API_URL}/login", data={"username": user, "password": pwd}, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                config.SESSION_TOKEN = data["access_token"]
                config.USER_ROLE = data["role"]
                config.USER_NAME = user
                config.USER_MEMBERSHIP = data["membresia"]
                
                config.USER_EXPIRY = "LIFETIME / INDEFINIDO"
                if "vencimiento" in data and data["vencimiento"]:
                    config.USER_EXPIRY = data["vencimiento"]
                else:
                    headers = {"Authorization": f"Bearer {config.SESSION_TOKEN}"}
                    try:
                        r_me = requests.get(f"{config.API_URL}/users/me", headers=headers, timeout=5)
                        if r_me.status_code == 200:
                            val = r_me.json().get("vencimiento")
                            if val: config.USER_EXPIRY = val
                        else:
                            r_user = requests.get(f"{config.API_URL}/users/{user}", headers=headers, timeout=3)
                            if r_user.status_code == 200:
                                val = r_user.json().get("vencimiento")
                                if val: config.USER_EXPIRY = val
                            elif config.USER_ROLE == 'admin':
                                r_all = requests.get(f"{config.API_URL}/users", headers=headers, timeout=5)
                                if r_all.status_code == 200:
                                    for u in r_all.json():
                                        if u['username'] == user and u.get('vencimiento'):
                                            config.USER_EXPIRY = u['vencimiento']
                                            break
                    except: pass

                self.controller.switch_frame(MenuFrame)
            else: 
                messagebox.showerror("Access Denied", f"Credenciales inválidas.\nStatus: {resp.status_code}")
        except Exception as e: 
            messagebox.showerror("Error de Conexión", f"No se pudo conectar al servidor.\n\nDetalle: {e}")

class MenuFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        
        self.anim = CyberRain(self, COLOR_ACCENT)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()

        # 1. Cabecera con Logo
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(pady=(20, 10))

        try:
            img_path = utils.resource_path("Scanneler.png")
            if os.path.exists(img_path):
                pil_img = Image.open(img_path)
                self.logo_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(100, 100))
                ctk.CTkLabel(header_frame, image=self.logo_img, text="").pack()
        except: pass

        ctk.CTkLabel(header_frame, text="SCANNELER", font=("Segoe UI", 32, "bold"), text_color="white").pack(pady=(5, 0))
        
        info_text = f"AGENT: {config.USER_NAME.upper()}  |  PLAN: {config.USER_MEMBERSHIP.upper()}" if config.USER_NAME else "DEV MODE"
        ctk.CTkLabel(header_frame, text=info_text, font=("Consolas", 12), text_color=COLOR_ACCENT).pack()
        
        # 2. Grid Central
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=40, pady=10)
        main.rowconfigure(0, weight=1)
        
        if config.USER_ROLE == 'admin':
            main.columnconfigure((0, 1, 2), weight=1)
            self.create_card(main, config.t("menu_scanner"), config.t("sub_scanner"), COLOR_ACCENT, self.go_user, 0, 0)
            self.create_card(main, config.t("menu_admin"), config.t("sub_admin"), COLOR_DANGER, self.go_admin, 0, 1)
            self.create_card(main, config.t("menu_settings"), config.t("sub_settings"), "#888", self.go_settings, 0, 2)
        else:
            main.columnconfigure((0, 1), weight=1)
            self.create_card(main, config.t("menu_scanner"), config.t("sub_scanner"), COLOR_ACCENT, self.go_user, 0, 0)
            self.create_card(main, config.t("menu_settings"), config.t("sub_settings"), "#888", self.go_settings, 0, 1)

        # 3. Footer
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.pack(side="bottom", pady=(0, 20))
        
        ctk.CTkLabel(footer_frame, text=config.t("footer_contact"), font=("Consolas", 11), text_color=COLOR_ACCENT).pack()
        ctk.CTkLabel(footer_frame, text=config.t("footer_made"), font=("Segoe UI", 12, "bold"), text_color=COLOR_ACCENT).pack()

        ctk.CTkButton(self, text=config.t("btn_disconnect"), command=sys.exit, fg_color="transparent", border_width=1, border_color=COLOR_BORDER, text_color="#aaa", width=150, height=30).pack(side="bottom", pady=10)

    def cleanup(self): self.anim.detener()

    def create_card(self, parent, title, subtitle, color, cmd, r, c):
        card = ModernCard(parent)
        card.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")
        
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center", relwidth=1)

        ctk.CTkLabel(inner, text=title, font=("Segoe UI", 18, "bold"), text_color=color).pack(pady=(5, 2))
        ctk.CTkLabel(inner, text=subtitle, font=("Segoe UI", 11), text_color="#888").pack(pady=(0, 15))
        
        ctk.CTkButton(inner, text=config.t("btn_open"), command=cmd, fg_color="transparent", border_width=1, border_color=color, text_color=color, hover_color="#220033", width=100, height=32, font=("Segoe UI", 11, "bold")).pack()

    def go_admin(self): self.controller.switch_frame(AdminFrame)
    def go_user(self): self.controller.switch_frame(UserConfigFrame)
    def go_settings(self): self.controller.switch_frame(SettingsFrame)

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        
        self.anim = CyberRain(self, "#888")
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()

        ctk.CTkLabel(self, text=config.t("set_title"), font=("Segoe UI", 24), text_color="white").pack(pady=50)
        
        f = ModernCard(self)
        f.pack(padx=100, pady=20, fill="x")
        
        ctk.CTkLabel(f, text=config.t("lbl_lang"), font=("Segoe UI", 14, "bold"), text_color=COLOR_TEXT).pack(pady=20)
        
        btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        col_es = COLOR_ACCENT if config.CURRENT_LANGUAGE=="es" else "#222"
        text_es = "black" if config.CURRENT_LANGUAGE=="es" else "white"
        
        col_en = COLOR_ACCENT if config.CURRENT_LANGUAGE=="en" else "#222"
        text_en = "black" if config.CURRENT_LANGUAGE=="en" else "white"
        
        ctk.CTkButton(btn_frame, text="ESPAÑOL", command=lambda: self.set_lang("es"), fg_color=col_es, text_color=text_es).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="ENGLISH", command=lambda: self.set_lang("en"), fg_color=col_en, text_color=text_en).pack(side="left", padx=10)
        
        ctk.CTkButton(self, text=config.t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), fg_color="transparent", border_width=1, border_color=COLOR_BORDER, text_color="#aaa", hover_color="#220033").pack(pady=50)

    def cleanup(self): self.anim.detener()

    def set_lang(self, l):
        config.CURRENT_LANGUAGE = l
        self.controller.switch_frame(SettingsFrame)

class UserConfigFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        self.ui_map = {}
        self.rutas = config.HISTORIAL_RUTAS.copy()
        
        self.anim = CyberRain(self, COLOR_ACCENT)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=320, corner_radius=0, fg_color=COLOR_PANEL)
        sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(sidebar, text=config.t("cfg_title"), font=("Segoe UI", 20, "bold"), text_color="white").pack(pady=(40, 30), padx=30, anchor="w")
        
        self.create_input(sidebar, config.t("lbl_path"), self.rutas['path'], self.select_path)
        self.create_input(sidebar, config.t("lbl_folder"), self.rutas['folder'], None)
        self.create_input(sidebar, config.t("lbl_list"), self.rutas['list_path'], self.select_list)
        self.create_input(sidebar, config.t("lbl_target"), "", self.select_target)
        
        ctk.CTkFrame(sidebar, height=1, fg_color=COLOR_BORDER).pack(fill="x", padx=30, pady=30)
        
        ctk.CTkButton(sidebar, text=config.t("btn_start"), command=self.go, height=50, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color="black", font=("Segoe UI", 14, "bold")).pack(fill="x", padx=30, pady=10)
        ctk.CTkButton(sidebar, text=config.t("btn_back"), command=lambda: controller.switch_frame(MenuFrame), height=40, fg_color="transparent", border_width=1, border_color=COLOR_BORDER, text_color="#aaa", hover_color="#220033").pack(fill="x", padx=30)

        if config.USER_EXPIRY and str(config.USER_EXPIRY).lower() != "none":
            expiry_text = str(config.USER_EXPIRY).upper()
        else:
            expiry_text = "LIFETIME / INDEFINIDO"

        info_box = ctk.CTkFrame(sidebar, fg_color="transparent")
        info_box.pack(fill="x", padx=30, pady=(20, 0))
        
        ctk.CTkLabel(info_box, text=config.t("lbl_expiry"), font=("Segoe UI", 10, "bold"), text_color="#888").pack()
        ctk.CTkLabel(info_box, text=expiry_text, font=("Consolas", 12, "bold"), text_color=COLOR_SUCCESS).pack()

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
        
        head_mod = ctk.CTkFrame(main, fg_color="transparent")
        head_mod.pack(fill="x", pady=(10, 10))
        ctk.CTkLabel(head_mod, text=config.t("lbl_modules"), font=("Segoe UI", 18, "bold"), text_color="#fff").pack(side="left")
        ctk.CTkButton(head_mod, text=config.t("btn_all"), command=lambda: self.toggle(True), width=60, height=25, fg_color="#333").pack(side="right")
        ctk.CTkButton(head_mod, text=config.t("btn_none"), command=lambda: self.toggle(False), width=60, height=25, fg_color="#222").pack(side="right", padx=10)

        scroll = ctk.CTkScrollableFrame(main, fg_color="transparent")
        scroll.pack(fill="both", expand=True)
        scroll.grid_columnconfigure((0,1), weight=1)

        modules = [
            (config.t("f1"), 'f1'), (config.t("f2"), 'f2'), (config.t("f3"), 'f3'),
            (config.t("f4"), 'f4'), (config.t("f5"), 'f5'), (config.t("f6"), 'f6'),
            (config.t("f7"), 'f7'), (config.t("f8"), 'f8'), (config.t("f9"), 'f9'),
            (config.t("f10"), 'f10'), (config.t("f11"), 'f11'), (config.t("f12"), 'f12'),
            (config.t("f13"), 'f13'), (config.t("f14"), 'f14'), (config.t("f15"), 'f15'),
            (config.t("f16"), 'f16'), (config.t("f17"), 'f17'), (config.t("f18"), 'f18'),
            (config.t("f19"), 'f19'), (config.t("f20"), 'f20'), (config.t("f21"), 'f21'),
            (config.t("f22"), 'f22'), (config.t("f23"), 'f23'), (config.t("f24"), 'f24'),
            (config.t("f25"), 'f25'), (config.t("f26"), 'f26'), (config.t("vt"), 'vt')
        ]
        
        perms = {'Basic': ['f1','f2','f3','f5','f7','f8','f9','f18','f20'], 
                 'Medium': ['f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12','f18','f20','vt'], 
                 'Full': [m[1] for m in modules]}
        self.alwd = perms.get(config.USER_MEMBERSHIP, [])

        r, c = 0, 0
        for text, key in modules:
            self.create_module_card(scroll, text, key, r, c)
            c += 1
            if c > 1: c = 0; r += 1

    def cleanup(self): self.anim.detener()

    def create_input(self, parent, title, val, cmd):
        ctk.CTkLabel(parent, text=title, font=("Segoe UI", 10, "bold"), text_color="#aaa").pack(anchor="w", padx=30, pady=(15, 5))
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=30)
        e = ctk.CTkEntry(f, border_color=COLOR_BORDER, height=35, fg_color="#1a002a")
        e.pack(side="left", fill="x", expand=True)
        if val: e.insert(0, val)
        if cmd: ctk.CTkButton(f, text="...", width=35, command=cmd, fg_color="#222", hover_color="#333").pack(side="right", padx=(5, 0))
        
        if title == config.t("lbl_path"): self.pv = e
        elif title == config.t("lbl_folder"): self.fv = e
        elif title == config.t("lbl_list"): self.lv = e
        elif title.startswith(config.t("lbl_target").split()[0]): self.tv = e

    def create_module_card(self, parent, text, key, r, c):
        active = key in self.alwd
        color = "#1a002a" if active else "#0a0010"
        card = ctk.CTkFrame(parent, fg_color=color, corner_radius=10, border_width=1, border_color="#2a003a")
        card.grid(row=r, column=c, padx=8, pady=8, sticky="ew")
        
        var = ctk.BooleanVar(value=active)
        state = "normal" if active else "disabled"
        
        sw = ctk.CTkSwitch(card, text=text, variable=var, state=state, progress_color=COLOR_ACCENT, font=("Segoe UI", 12))
        sw.pack(side="left", padx=15, pady=15)
        
        mode = tk.StringVar(value=config.t("opt_list"))
        
        if active and key != 'vt':
            if key == 'f5':
                ctk.CTkOptionMenu(card, variable=mode, values=[config.t("opt_list")], width=110, height=24, fg_color="#222", button_color="#333", state="disabled").pack(side="right", padx=15)
            else:
                ctk.CTkOptionMenu(card, variable=mode, values=[config.t("opt_list"), config.t("opt_all")], width=110, height=24, fg_color="#222", button_color="#333").pack(side="right", padx=15)
        
        self.ui_map[key] = {'active': var, 'modo': mode}

    def select_path(self):
        p = filedialog.askdirectory()
        if p: self.pv.delete(0, tk.END); self.pv.insert(0, p)
    def select_list(self):
        f = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if f: self.lv.delete(0, tk.END); self.lv.insert(0, f)
    def select_target(self):
        f = filedialog.askopenfilename()
        if f: self.tv.delete(0, tk.END); self.tv.insert(0, f)
    def toggle(self, val):
        for k, v in self.ui_map.items():
            if k in self.alwd: v['active'].set(val)
    def go(self):
        config.HISTORIAL_RUTAS['path'] = self.pv.get()
        config.HISTORIAL_RUTAS['folder'] = self.fv.get()
        config.HISTORIAL_RUTAS['list_path'] = self.lv.get()
        config.HISTORIAL_RUTAS['target_file'] = self.tv.get()
        sel = {k: {'active': v['active'].get(), 'modo': v['modo'].get()} for k, v in self.ui_map.items()}
        pals = utils.cargar_palabras(config.HISTORIAL_RUTAS['list_path'])
        self.controller.switch_frame(ScannerFrame, pals, sel, config.HISTORIAL_RUTAS)

class ScannerFrame(ctk.CTkFrame):
    def __init__(self, parent, controller, palabras, configuracion, rutas):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        self.config = configuracion
        self.rutas = rutas
        config.CANCELAR_ESCANEO = False
        
        self.anim = CyberRain(self, COLOR_SUCCESS)
        self.anim.place(relx=0, rely=0, relwidth=1, relheight=1)
        # CORREGIDO: Eliminado self.anim.lower()
        
        box = ctk.CTkFrame(self, fg_color="#0a0010", corner_radius=20, border_color=COLOR_BORDER, border_width=1)
        box.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.6, relheight=0.5)
        
        ctk.CTkLabel(box, text=config.t("scan_title"), font=("Segoe UI", 32, "bold"), text_color="white").pack(pady=(50, 10))
        
        self.pb = ctk.CTkProgressBar(box, width=450, height=8, progress_color=COLOR_SUCCESS, border_color="#222")
        self.pb.pack(pady=20)
        self.pb.configure(mode="indeterminate"); self.pb.start()
        
        self.lbl_status = ctk.CTkLabel(box, text=config.t("scan_init"), font=("Consolas", 14), text_color="#888")
        self.lbl_status.pack(pady=10)
        
        ctk.CTkButton(box, text=config.t("btn_abort"), command=self.stop, fg_color=COLOR_DANGER, hover_color="#990000", height=45, width=200).pack(pady=40)
        
        self.cola_estado = Queue()
        threading.Thread(target=self.run_scan, daemon=True).start()
        self.check_queue()

    def cleanup(self): self.anim.detener()
    def stop(self): config.CANCELAR_ESCANEO = True
    def update_status(self, msg): self.cola_estado.put(msg)
    def check_queue(self):
        try:
            while not self.cola_estado.empty():
                msg = self.cola_estado.get_nowait()
                if msg == "DONE": 
                    self.anim.detener()
                    messagebox.showinfo(config.t("scan_done_title"), f"{config.t('scan_done_msg')}\n{self.fp}")
                    self.controller.switch_frame(MenuFrame)
                else: self.lbl_status.configure(text=msg)
        except: pass
        if not config.CANCELAR_ESCANEO: self.after(100, self.check_queue)
        else: self.controller.switch_frame(MenuFrame)

    def run_scan(self):
        bd = self.rutas.get('path', os.path.abspath(".")); fn = self.rutas.get('folder', "Resultados_SS")
        fp = os.path.join(bd, fn)
        if not os.path.exists(fp): os.makedirs(fp, exist_ok=True)
        self.fp = fp
        
        config.reporte_game = os.path.join(fp, "Game_Cheat_Hunter.txt")
        config.reporte_usb = os.path.join(fp, "USB_History.txt")
        config.reporte_shim = os.path.join(fp, "ShimCache.txt")
        config.reporte_dna = os.path.join(fp, "DNA_Prefetch.txt")
        config.reporte_vt = os.path.join(fp, "VirusTotal.txt")
        config.reporte_nuclear = os.path.join(fp, "Nuclear_Traces.txt")
        
        try: scanner_engine.generar_reporte_html(fp, self.config)
        except: pass
        
        vte = self.config.get('vt', {}).get('active', False)
        if vte:
             with open(config.reporte_vt, "w", encoding="utf-8") as f: f.write(f"=== VT: {datetime.datetime.now()} ===\n\n")
             threading.Thread(target=scanner_engine.worker_virustotal, daemon=True).start()

        fases = [
            ('f1', scanner_engine.fase_shimcache),
            ('f2', scanner_engine.fase_rastro_appcompat),
            ('f3', scanner_engine.fase_nombre_original),
            ('f4', scanner_engine.fase_verificar_firmas),
            ('f5', scanner_engine.fase_buscar_en_disco),
            ('f6', scanner_engine.fase_archivos_ocultos),
            ('f7', scanner_engine.fase_mft_ads),
            ('f8', scanner_engine.fase_userassist),
            ('f9', scanner_engine.fase_usb_history),
            ('f10', scanner_engine.fase_dns_cache),
            ('f11', scanner_engine.fase_browser_forensics),
            ('f12', scanner_engine.fase_persistence),
            ('f13', scanner_engine.fase_event_logs),
            ('f14', scanner_engine.fase_process_hunter),
            ('f15', scanner_engine.fase_game_cheat_hunter),
            ('f16', scanner_engine.fase_nuclear_traces),
            ('f17', scanner_engine.fase_kernel_hunter),
            ('f18', scanner_engine.fase_dna_prefetch),
            ('f19', scanner_engine.fase_network_hunter),
            ('f20', scanner_engine.fase_toxic_lnk),
            ('f21', scanner_engine.fase_ghost_trails),
            ('f22', scanner_engine.fase_memory_anomaly),
            ('f23', scanner_engine.fase_rogue_drivers),
            ('f24', scanner_engine.fase_deep_static),
            ('f25', scanner_engine.fase_metamorphosis_hunter),
            ('f26', scanner_engine.fase_string_cleaning)
        ]
        
        # Inicializar contexto
        context = scanner_engine.ScannerContext()
        self.update_status("Taking System Snapshot...")
        context.prepare()

        for k, func in fases:
            if config.CANCELAR_ESCANEO: break
            
            conf_fase = self.config.get(k, {})
            if conf_fase.get('active'):
                self.update_status(f"Running Module: {k.upper()}...")
                modo = conf_fase.get('modo', config.t("opt_list"))
                
                try: 
                    # Lógica de argumentos dinámica
                    args = []
                    
                    # Fases que usan contexto
                    if k in ['f3', 'f5', 'f6', 'f14', 'f15', 'f25']:
                        if k == 'f3' or k == 'f4': args = [context, self.palabras, vte, modo]
                        elif k == 'f25': args = [context, self.palabras, modo, self.rutas.get('target_file')]
                        else: args = [context, self.palabras, modo]
                    else:
                        # Fases legacy (sin contexto)
                        if k in ['f1','f2','f7','f8','f9','f10','f11','f12','f13','f16','f17','f18','f19','f20','f21','f22','f23','f24','f26']:
                             args = [self.palabras, modo]

                    func(*args)
                except Exception as e: print(f"Error {k}: {e}")
                time.sleep(0.1)

        scanner_engine.cola_vt.put(None)
        if vte:
            self.update_status("Finalizing Cloud Analysis...")
            scanner_engine.cola_vt.join()

        if not config.CANCELAR_ESCANEO: 
             try: scanner_engine.generar_reporte_global_cheats(fp)
             except: pass
             self.cola_estado.put("DONE")

class ScannelerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SCANNELER V.2026")
        
        w, h = 1100, 750
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws/2) - (w/2)
        y = (hs/2) - (h/2)
        self.geometry('%dx%d+%d+%d' % (w, h, x, y))
        self.minsize(1000, 700)
        self.configure(fg_color=COLOR_BG)
        
        try: 
            icon_path = utils.resource_path("Scanneler.ico")
            if os.path.exists(icon_path): self.iconbitmap(icon_path)
        except: pass
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        
        self.frames = {}
        self.current_frame = None
        self.switch_frame(CargaDinamicaFrame)

    def switch_frame(self, frame_class, *args, **kwargs):
        if self.current_frame:
            if hasattr(self.current_frame, 'cleanup'): self.current_frame.cleanup()
            self.current_frame.destroy()
            
        self.current_frame = frame_class(self.container, self, *args, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def on_close(self):
        config.CANCELAR_ESCANEO = True
        self.destroy()
        sys.exit()