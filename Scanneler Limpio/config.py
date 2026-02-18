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
        "lbl_memb": "MEMBERSHIP:",
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
        
        # TITULOS DE FASES
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
        "f27": "F27: Bypass Detecter",
        "f28": "F28: Inteligencia Amcache", # [NUEVO]
        "vt": "VT: VirusTotal Cloud",

        # DESCRIPCIONES DE FASES (ESPAÑOL)
        "f1_desc": "Muestra un historial de todos los programas ejecutados en la PC, incluso si el archivo ya fue borrado.",
        "f2_desc": "Rastrea aplicaciones que se abrieron recientemente y quedaron guardadas en la memoria de compatibilidad de Windows.",
        "f3_desc": "Detecta si alguien le cambió el nombre a un programa para esconderlo (Ej: renombrar 'cheat.exe' a 'chrome.exe').",
        "f4_desc": "Verifica si los programas son oficiales y seguros (Firmados Digitalmente) o si son archivos desconocidos/peligrosos.",
        "f5_desc": "Busca palabras clave sospechosas (nombres de hacks conocidos) dentro de las carpetas Descargas, Escritorio y Temporales.",
        "f6_desc": "Encuentra archivos que el usuario ocultó intencionalmente para que no sean vistos a simple vista.",
        "f7_desc": "Busca información oculta 'detrás' de archivos normales (técnica usada para esconder configuraciones de trampas).",
        "f8_desc": "Muestra una lista de programas y accesos directos que el usuario ha clickeado o abierto desde el Escritorio.",
        "f9_desc": "Historial de todos los Pendrives o discos USB conectados y lista de qué programas se ejecutaron desde ellos.",
        "f10_desc": "Revisa a qué sitios web se conectó la PC recientemente (útil para ver si visitaron páginas de venta de hacks).",
        "f11_desc": "Recupera el historial de descargas de navegadores (Chrome, Edge, etc.), incluso si lo borraron del navegador.",
        "f12_desc": "Detecta programas configurados para iniciarse solos apenas se prende la computadora (Auto-arranque).",
        "f13_desc": "Busca registros de errores del sistema que ocurren cuando un programa inestable (como un cheat) intenta funcionar.",
        "f14_desc": "Analiza todo lo que se está ejecutando AHORA MISMO en la memoria de la PC.",
        "f15_desc": "Buscador especializado que escanea el disco buscando trampas o hacks específicos de juegos conocidos.",
        "f16_desc": "Informe detallado con fecha y hora exacta de cada programa ejecutado. Muestra si sigue abierto o si ya se cerró.",
        "f17_desc": "Revisa si el núcleo (corazón) de Windows fue modificado para permitir trampas avanzadas.",
        "f18_desc": "Analiza la carpeta 'Prefetch' para mostrar cuándo fue la primera y última vez que se usó un programa.",
        "f19_desc": "Examina las conexiones a internet activas y comandos recientes de red sospechosos.",
        "f20_desc": "Analiza los accesos directos del sistema para ver si apuntan a archivos sospechosos o que fueron eliminados.",
        "f21_desc": "Rastrea qué archivos (imágenes, textos, programas) abrió el usuario recientemente en el explorador.",
        "f22_desc": "Escanea la memoria RAM buscando código intruso inyectado dentro de otros programas legítimos.",
        "f23_desc": "Detecta controladores (drivers) peligrosos o no oficiales cargados en el sistema.",
        "f24_desc": "Detecta archivos 'encriptados' o comprimidos de forma extraña (comportamiento típico de virus y cheats privados).",
        "f25_desc": "Busca copias exactas de un archivo sospechoso en todo el disco, aunque le hayan cambiado el nombre.",
        "f26_desc": "Detecta si el usuario borró archivos masivamente o usó herramientas de limpieza recientemente para esconder evidencia.",
        "f27_desc": "Detecta programas ejecutados que se autodestruyeron, archivos huérfanos y manipulación de registros forenses (Bypass Detecter).",
        "f28_desc": "Analiza la identidad real (Hash y Metadatos) de los archivos. Revela el nombre original de fábrica para detectar si un programa fue renombrado para camuflarse.", # [NUEVO]
        "vt_desc": "Sube el Hash de los archivos a la nube de VirusTotal para ver si 70 antivirus los detectan como maliciosos."
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
        "f27": "F27: Master Anti-Forensics (Bypass Detecter)",
        "f28": "F28: Amcache Full Intelligence", # [NUEVO]
        "vt": "VT: VirusTotal Cloud",

        # DESCRIPCIONES DE FASES (ENGLISH)
        "f1_desc": "Shows a history of all programs executed on the PC, even if the file has already been deleted.",
        "f2_desc": "Tracks applications that were recently opened and stored in Windows compatibility memory.",
        "f3_desc": "Detects if someone renamed a program to hide it (e.g., renaming 'cheat.exe' to 'chrome.exe').",
        "f4_desc": "Verifies if programs are official and safe (Digitally Signed) or unknown/dangerous files.",
        "f5_desc": "Searches for suspicious keywords (known hack names) in Downloads, Desktop, and Temp folders.",
        "f6_desc": "Finds files that the user intentionally hid to avoid detection.",
        "f7_desc": "Looks for hidden information 'behind' normal files (technique used to hide cheat configs).",
        "f8_desc": "Shows a list of programs and shortcuts the user has clicked or opened from the Desktop.",
        "f9_desc": "History of all USB drives connected and a list of programs executed from them.",
        "f10_desc": "Checks recently visited websites (useful to see if they visited hack selling sites).",
        "f11_desc": "Recovers browser download history (Chrome, Edge, etc.), even if cleared from the browser.",
        "f12_desc": "Detects programs configured to start automatically when the computer turns on.",
        "f13_desc": "Searches for system error logs that occur when unstable software (like a cheat) tries to run.",
        "f14_desc": "Analyzes everything currently running in the PC's memory.",
        "f15_desc": "Specialized scanner that searches the disk for specific cheats or hacks for known games.",
        "f16_desc": "Detailed report with exact date/time of each executed program. Shows if it's still open or closed.",
        "f17_desc": "Checks if the Windows kernel (core) has been modified to allow advanced cheats.",
        "f18_desc": "Analyzes the 'Prefetch' folder to show when a program was first and last used.",
        "f19_desc": "Examines active internet connections and recent suspicious network commands.",
        "f20_desc": "Analyses system shortcuts to see if they point to suspicious or deleted files.",
        "f21_desc": "Tracks files (images, texts, programs) the user recently opened in Explorer.",
        "f22_desc": "Scans RAM for intrusive code injected into other legitimate programs.",
        "f23_desc": "Detects dangerous or unofficial drivers loaded into the system.",
        "f24_desc": "Detects 'encrypted' or strangely compressed files (typical behavior of viruses and private cheats).",
        "f25_desc": "Searches for exact copies of a suspicious file across the entire disk, even if renamed.",
        "f26_desc": "Detects if the user mass-deleted files or used cleaning tools recently to hide evidence.",
        "f27_desc": "Detects programs that self-destructed, orphan files, and forensic record tampering (Bypass Detecter).",
        "f28_desc": "Analyzes the real identity (Hash & Metadata) of files. Reveals the original factory name to detect if a program was renamed to camouflage itself.", # [NUEVO]
        "vt_desc": "Uploads file Hash to VirusTotal cloud to see if 70 antiviruses detect them as malicious."
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
reporte_antiforensics = "" # [F27] - Bypass Detecter
reporte_amcache = ""       # [F28] - Amcache Intelligence
reporte_vt = "detecciones_virustotal.txt"