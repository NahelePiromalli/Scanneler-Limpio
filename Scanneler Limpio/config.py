import os
import sys

# =============================================================================
# VARIABLES GLOBALES Y ESTADO
# =============================================================================

# Rutas y Estado
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

# YARA
GLOBAL_YARA_RULES = None

# Idioma
CURRENT_LANGUAGE = "es"

TRADUCCIONES = {
    "es": {
        "login_title": "AUTENTICACIÓN",
        "user_ph": "USUARIO",
        "pass_ph": "CONTRASEÑA",
        "btn_connect": "CONECTAR",
        "btn_redeem": "CANJEAR LICENCIA",
        "btn_exit": "SALIR",
        "menu_admin": "PANEL ADMIN",
        "menu_user": "SCANNER",
        "menu_settings": "AJUSTES",
        "welcome": "BIENVENIDO",
        "scan_config": "CONFIGURACIÓN",
        "path_lbl": "RUTA REPORTE:",
        "folder_lbl": "CARPETA:",
        "list_lbl": "LISTA PALABRAS:",
        "target_lbl": "ARCHIVO TARGET:", 
        "btn_select": "SELECCIONAR",
        "btn_browse": "BUSCAR",
        "btn_pick": "ELEGIR",
        "modules_lbl": "MÓDULOS DE DETECCIÓN:",
        "sel_all": "TODOS",
        "desel_all": "NINGUNO",
        "upgrade": "MEJORA TU PLAN",
        "only_list": "Modo Lista",
        "btn_start": "INICIAR ESCANEO",
        "btn_back": "VOLVER",
        "audit_prog": "AUDITORÍA EN PROGRESO...",
        "init": "Inicializando...",
        "stop_scan": "DETENER",
        "settings_title": "CONFIGURACIÓN",
        "lang_lbl": "SELECCIONAR IDIOMA / SELECT LANGUAGE",
        "success_update": "Idioma actualizado correctamente."
    },
    "en": {
        "login_title": "AUTHENTICATION",
        "user_ph": "USERNAME",
        "pass_ph": "PASSWORD",
        "btn_connect": "CONNECT",
        "btn_redeem": "REDEEM LICENSE",
        "btn_exit": "EXIT",
        "menu_admin": "ADMIN PANEL",
        "menu_user": "SCANNER",
        "menu_settings": "SETTINGS",
        "welcome": "WELCOME",
        "scan_config": "CONFIGURATION",
        "path_lbl": "OUTPUT PATH:",
        "folder_lbl": "FOLDER NAME:",
        "list_lbl": "KEYWORD LIST:",
        "target_lbl": "TARGET FILE:",
        "btn_select": "SELECT",
        "btn_browse": "BROWSE",
        "btn_pick": "CHOOSE",
        "modules_lbl": "DETECTION MODULES:",
        "sel_all": "ALL",
        "desel_all": "NONE",
        "upgrade": "UPGRADE PLAN",
        "only_list": "List Mode",
        "btn_start": "START SCAN",
        "btn_back": "BACK",
        "audit_prog": "AUDIT IN PROGRESS...",
        "init": "Initializing...",
        "stop_scan": "STOP SCAN",
        "settings_title": "SYSTEM SETTINGS",
        "lang_lbl": "SELECT LANGUAGE / SELECCIONAR IDIOMA",
        "success_update": "Language updated successfully."
    }
}

def t(key):
    return TRADUCCIONES.get(CURRENT_LANGUAGE, TRADUCCIONES["es"]).get(key, key)

# ==========================================
# PALETA DE COLORES (VIOLET EDITION 2026)
# ==========================================
COLOR_BG = "#020005"            # Fondo casi negro con tinte violeta
COLOR_CARD = "#12001F"          # Tarjetas violeta muy oscuro
COLOR_ACCENT = "#D500F9"        # Violeta Neón Brillante (Principal)
COLOR_ACCENT_HOVER = "#A000C8"  # Violeta Oscuro para Hover
COLOR_DANGER = "#FF0055"        # Rojo Rosado Neon
COLOR_SUCCESS = "#00E676"       # Verde Neon (Contraste)
COLOR_TEXT = "#E0B0FF"          # Blanco Lila
COLOR_BORDER = "#4A0072"        # Bordes Púrpura

# Nombres de Reportes
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