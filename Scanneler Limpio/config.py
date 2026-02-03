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
        "login_title": "ACCESO AL SISTEMA",
        "user_lbl": "USUARIO",
        "pass_lbl": "CONTRASEÑA",
        "btn_login": "INICIAR SESIÓN",
        "btn_redeem": "CANJEAR LICENCIA",
        "btn_exit": "SALIR",
        "menu_admin": "PANEL ADMIN",
        "menu_user": "PANEL USUARIO",
        "menu_settings": "CONFIGURACIÓN",
        "welcome": "BIENVENIDO",
        "scan_config": "CONFIGURACIÓN DE ESCANEO",
        "path_lbl": "RUTA REPORTE:",
        "folder_lbl": "NOMBRE CARPETA:",
        "list_lbl": "LISTA PALABRAS:",
        "target_lbl": "ARCHIVO TARGET:", 
        "btn_select": "SELECCIONAR",
        "btn_browse": "BUSCAR",
        "btn_pick": "ELEGIR",
        "modules_lbl": "MÓDULOS DE DETECCIÓN:",
        "sel_all": "[ MARCAR TODOS ]",
        "desel_all": "[ DESMARCAR ]",
        "upgrade": "MEJORA TU PLAN",
        "only_list": "Solo Modo Lista",
        "btn_start": "INICIAR MOTOR DE ESCANEO",
        "btn_back": "VOLVER AL MENÚ",
        "audit_prog": "AUDITORÍA EN PROGRESO...",
        "init": "Inicializando...",
        "stop_scan": "DETENER ESCANEO",
        "settings_title": "CONFIGURACIÓN DEL SISTEMA",
        "lang_lbl": "SELECCIONAR IDIOMA / SELECT LANGUAGE",
        "success_update": "Idioma actualizado correctamente."
    },
    "en": {
        "login_title": "SYSTEM ACCESS",
        "user_lbl": "USERNAME",
        "pass_lbl": "PASSWORD",
        "btn_login": "LOGIN",
        "btn_redeem": "REDEEM LICENSE",
        "btn_exit": "EXIT",
        "menu_admin": "ADMIN PANEL",
        "menu_user": "USER PANEL",
        "menu_settings": "SETTINGS",
        "welcome": "WELCOME",
        "scan_config": "SCANNER CONFIGURATION",
        "path_lbl": "OUTPUT PATH:",
        "folder_lbl": "FOLDER NAME:",
        "list_lbl": "KEYWORD LIST:",
        "target_lbl": "TARGET FILE:",
        "btn_select": "SELECT",
        "btn_browse": "BROWSE",
        "btn_pick": "CHOOSE",
        "modules_lbl": "DETECTION MODULES:",
        "sel_all": "[ SELECT ALL ]",
        "desel_all": "[ DESELECT ALL ]",
        "upgrade": "UPGRADE PLAN",
        "only_list": "List Mode Only",
        "btn_start": "START SCAN ENGINE",
        "btn_back": "BACK TO MENU",
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

# Colores Cyberpunk
COLOR_SUCCESS = "#69f0ae"   
COLOR_BG = "#090011"        
COLOR_CARD = "#1a0526"      
COLOR_ACCENT = "#d500f9"    
COLOR_USER = "#b388ff"      
COLOR_TEXT = "#f3e5f5"      
COLOR_BORDER = "#4a148c"    
COLOR_HOVER_BG = "#4a0072"  
COLOR_HOVER_BORDER = "#ff40ff"
COLOR_DANGER = "#ff1744"    
COLOR_CLICK = "#000000"     

# Nombres de Reportes (Se actualizan dinamicamente con la ruta completa)
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