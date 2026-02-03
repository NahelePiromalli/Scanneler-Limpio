import os
import sys

# =============================================================================
# VARIABLES GLOBALES Y ESTADO
# =============================================================================

# Rutas y Estado de la Aplicación
HISTORIAL_RUTAS = {
    'path': os.path.abspath("."),
    'folder': 'Resultados_SS',
    'list_path': "lista.txt",
    'target_file': None
}

WINDOW_STATE = {"maximized": False}
CANCELAR_ESCANEO = False

# API y Sesión
VT_API_KEY = "38885e277f7dc078cf8690f9315fddda65966c4ec0208dbc430a8fb91bb7c359" 
API_URL = "https://scanneler-api.onrender.com"

SESSION_TOKEN = None
USER_ROLE = None
USER_NAME = None
USER_MEMBERSHIP = None
USER_EXPIRY = None

# YARA Rules (Cargadas en memoria)
GLOBAL_YARA_RULES = None

# Idioma Actual ('es' o 'en')
CURRENT_LANGUAGE = "es"

# =============================================================================
# SISTEMA DE TRADUCCIÓN (DICCIONARIO COMPLETO)
# =============================================================================
TRADUCCIONES = {
    "es": {
        # LOGIN
        "login_title": "ACCESO SEGURO",
        "login_sub": "VERIFICACIÓN DE IDENTIDAD",
        "user_ph": "USUARIO",
        "pass_ph": "CONTRASEÑA",
        "btn_connect": "CONECTAR SISTEMA",
        "btn_redeem": "CANJEAR KEY",
        "btn_exit": "SALIR",
        
        # MENU PRINCIPAL
        "menu_scanner": "ESCANER",
        "sub_scanner": "Auditoría Forense",
        "menu_admin": "PANEL ADMIN",
        "sub_admin": "Base de Datos & Keys",
        "menu_settings": "AJUSTES",
        "sub_settings": "Preferencias",
        "btn_disconnect": "DESCONECTAR",
        "btn_open": "ABRIR",
        "footer_made": "Creado por Jeler33",
        "footer_contact": "Contacto: Scanneler.Jeler33@gmail.com",

        # CONFIGURACIÓN DE USUARIO
        "cfg_title": "CONFIGURACIÓN",
        "lbl_path": "RUTA REPORTE",
        "lbl_folder": "NOMBRE CARPETA",
        "lbl_list": "LISTA PALABRAS",
        "lbl_target": "ARCHIVO OBJETIVO (F25)",
        "lbl_expiry": "VENCIMIENTO MEMBRESÍA:",
        "btn_start": "INICIAR ESCANEO",
        "btn_back": "VOLVER",
        "lbl_modules": "MÓDULOS DE DETECCIÓN",
        "btn_all": "Todo",
        "btn_none": "Nada",
        "opt_list": "Usar Lista",
        "opt_all": "Analizar Todo",

        # PANEL ADMIN
        "adm_title": "ADMINISTRACIÓN",
        "tab_users": "USUARIOS",
        "tab_licenses": "LICENCIAS",
        "lbl_edit_user": "EDITAR USUARIO:",
        "btn_update": "ACTUALIZAR",
        "btn_refresh": "RECARGAR",
        "lbl_gen_lic": "GENERADOR DE LICENCIAS",
        "lbl_memb": "MEMBRESÍA:",
        "lbl_dur": "DURACIÓN:",
        "lbl_qty": "CANTIDAD:",
        "btn_gen": "GENERAR KEYS",
        "lbl_log": "HISTORIAL:",
        "lbl_db": "BASE DE DATOS DE AGENTES",

        # PANTALLA DE ESCANEO
        "scan_title": "ESCANEO EN CURSO",
        "scan_init": "Inicializando Motor Neural...",
        "btn_abort": "ABORTAR OPERACIÓN",
        "scan_done_title": "Finalizado",
        "scan_done_msg": "Reporte guardado en:",

        # AJUSTES
        "set_title": "CONFIGURACIÓN DEL SISTEMA",
        "lbl_lang": "SELECCIONAR IDIOMA / SELECT LANGUAGE",
        
        # FASES (Nombres Oficiales)
        "f1": "F1: Análisis ShimCache",
        "f2": "F2: Rastros AppCompat",
        "f3": "F3: Chequeo Nombre Original",
        "f4": "F4: Firmas Digitales",
        "f5": "F5: Búsqueda en Disco",
        "f6": "F6: Archivos Ocultos",
        "f7": "F7: Análisis MFT & ADS",
        "f8": "F8: Historial UserAssist",
        "f9": "F9: Historial USB",
        "f10": "F10: Caché DNS",
        "f11": "F11: Forense Navegador",
        "f12": "F12: Persistencia Sistema",
        "f13": "F13: Event Logs Windows",
        "f14": "F14: Cazador Procesos",
        "f15": "F15: Game Cheat Hunter",
        "f16": "F16: Rastros Nucleares",
        "f17": "F17: Cazador Kernel",
        "f18": "F18: DNA & Prefetch",
        "f19": "F19: Conexiones Red",
        "f20": "F20: Archivos LNK Tóxicos",
        "f21": "F21: Rastros Fantasma",
        "f22": "F22: Anomalía Memoria",
        "f23": "F23: Drivers Maliciosos",
        "f24": "F24: Análisis Estático Deep",
        "f25": "F25: Cazador Metamorfosis",
        "f26": "F26: Limpieza de Strings",
        "vt": "VT: VirusTotal Cloud"
    },
    "en": {
        # LOGIN
        "login_title": "SECURE ACCESS",
        "login_sub": "IDENTITY VERIFICATION",
        "user_ph": "USERNAME",
        "pass_ph": "PASSWORD",
        "btn_connect": "CONNECT SYSTEM",
        "btn_redeem": "REDEEM KEY",
        "btn_exit": "EXIT",
        
        # MENU
        "menu_scanner": "SCANNER",
        "sub_scanner": "Forensic Audit",
        "menu_admin": "ADMIN PANEL",
        "sub_admin": "Database & Keys",
        "menu_settings": "SETTINGS",
        "sub_settings": "Preferences",
        "btn_disconnect": "DISCONNECT",
        "btn_open": "OPEN",
        "footer_made": "Made By Jeler33",
        "footer_contact": "Contact: Scanneler.Jeler33@gmail.com",

        # CONFIG USER
        "cfg_title": "CONFIGURATION",
        "lbl_path": "OUTPUT PATH",
        "lbl_folder": "FOLDER NAME",
        "lbl_list": "KEYWORD LIST",
        "lbl_target": "TARGET FILE (F25)",
        "lbl_expiry": "MEMBERSHIP EXPIRY:",
        "btn_start": "START SCAN",
        "btn_back": "BACK",
        "lbl_modules": "DETECTION MODULES",
        "btn_all": "All",
        "btn_none": "None",
        "opt_list": "Use List",
        "opt_all": "Scan All",

        # ADMIN
        "adm_title": "ADMINISTRATION",
        "tab_users": "USERS",
        "tab_licenses": "LICENSES",
        "lbl_edit_user": "EDIT USER:",
        "btn_update": "UPDATE",
        "btn_refresh": "REFRESH",
        "lbl_gen_lic": "LICENSE GENERATOR",
        "lbl_memb": "MEMBERSHIP:",
        "lbl_dur": "DURATION:",
        "lbl_qty": "QUANTITY:",
        "btn_gen": "GENERATE KEYS",
        "lbl_log": "HISTORY:",
        "lbl_db": "REGISTERED AGENTS DATABASE",

        # SCANNER
        "scan_title": "SCAN IN PROGRESS",
        "scan_init": "Initializing Neural Engine...",
        "btn_abort": "ABORT OPERATION",
        "scan_done_title": "Finished",
        "scan_done_msg": "Report saved at:",

        # SETTINGS
        "set_title": "SYSTEM SETTINGS",
        "lbl_lang": "SELECT LANGUAGE / SELECCIONAR IDIOMA",

        # PHASES
        "f1": "F1: ShimCache Analysis",
        "f2": "F2: AppCompat Traces",
        "f3": "F3: Identity Check",
        "f4": "F4: Digital Signatures",
        "f5": "F5: Disk Search",
        "f6": "F6: Hidden Files",
        "f7": "F7: MFT & ADS Analysis",
        "f8": "F8: UserAssist History",
        "f9": "F9: USB Forensics",
        "f10": "F10: DNS Cache",
        "f11": "F11: Browser Forensics",
        "f12": "F12: System Persistence",
        "f13": "F13: Windows Event Logs",
        "f14": "F14: Process Hunter",
        "f15": "F15: Game Cheat Hunter",
        "f16": "F16: Nuclear Traces",
        "f17": "F17: Kernel Hunter",
        "f18": "F18: DNA & Prefetch",
        "f19": "F19: Network Deep",
        "f20": "F20: Toxic LNKs",
        "f21": "F21: Ghost Trails",
        "f22": "F22: Memory Anomaly",
        "f23": "F23: Rogue Drivers",
        "f24": "F24: Deep Static Analysis",
        "f25": "F25: Metamorphosis Hunter",
        "f26": "F26: String Cleaning",
        "vt": "VT: VirusTotal Cloud"
    }
}

def t(key):
    """Devuelve el texto traducido según el idioma actual."""
    idioma = TRADUCCIONES.get(CURRENT_LANGUAGE, TRADUCCIONES["es"])
    return idioma.get(key, key) # Si no encuentra la key, devuelve la key misma

# =============================================================================
# PALETA DE COLORES (VIOLET EDITION 2026)
# =============================================================================
COLOR_BG = "#020005"            # Fondo casi negro
COLOR_CARD = "#12001F"          # Paneles violeta muy oscuro
COLOR_ACCENT = "#D500F9"        # Violeta Neón (Principal)
COLOR_ACCENT_HOVER = "#A000C8"  # Violeta Oscuro
COLOR_DANGER = "#FF0055"        # Rojo Neón
COLOR_SUCCESS = "#00E676"       # Verde Neón
COLOR_TEXT = "#E0B0FF"          # Texto Lila Claro
COLOR_BORDER = "#4A0072"        # Borde Púrpura

# =============================================================================
# RUTAS DE REPORTES (Inicialización)
# =============================================================================
# Se definen aquí vacías para que los módulos las puedan sobrescribir y usar
reporte_shim = ""
reporte_appcompat = ""
reporte_path = ""
reporte_sospechosos = ""
reporte_firmas = ""
reporte_ocultos = ""
reporte_mft = ""
reporte_userassist = ""
reporte_usb = "" 
reporte_dns = ""
reporte_browser = "" 
reporte_persistencia = ""
reporte_eventos = "" 
reporte_process = ""
reporte_game = ""    
reporte_nuclear = "" 
reporte_kernel = ""  
reporte_dna = ""      
reporte_network = "" 
reporte_toxic = "" 
reporte_ghost = ""
reporte_memory = ""
reporte_drivers = ""
reporte_static = ""
reporte_morph = ""
reporte_cleaning = ""
reporte_vt = "detecciones_virustotal.txt"