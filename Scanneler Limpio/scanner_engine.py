import os
import datetime
import pefile    # <--- Requiere pip install pefile
import subprocess
import ctypes
import sys
import winreg
import struct
import time
import requests  # <--- Requiere pip install requests
import codecs
import sqlite3
import json
import shutil
import re
import math
import uuid
import threading
import random    # <--- IMPORTANTE
from queue import Queue, Empty
from collections import Counter
import concurrent.futures
import psutil    # <--- Requiere pip install psutil
import hashlib
import html

# Importaciones locales
import config
from utils import resource_path, calculate_entropy, DisableFileSystemRedirection, MEMORY_BASIC_INFORMATION, filetime_to_dt

# Cola global
cola_vt = Queue()

def worker_virustotal():
    while not config.CANCELAR_ESCANEO:
        ruta = cola_vt.get()
        if ruta is None: 
            cola_vt.task_done()
            break
        try:
            with open(ruta, "rb") as f: file_hash = hashlib.sha256(f.read()).hexdigest()
            headers = {"x-apikey": config.VT_API_KEY}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0:
                    with open(config.reporte_vt, "a", encoding="utf-8", buffering=1) as f:
                        f.write(f"[{datetime.datetime.now()}] DETECTADO: {ruta}\n")
                        f.write(f" > Positivos: {stats['malicious']}\n")
                        f.write(f" > Hash: {file_hash}\n\n")
                        f.flush()
        except: pass
        cola_vt.task_done()
        
# =============================================================================
# HELPER: ASEGURAR RUTAS ABSOLUTAS (COPIA ESTO AL INICIO)
# =============================================================================
def asegurar_ruta_reporte(nombre_archivo):
    """
    Calcula la ruta absoluta basada en la configuración de la GUI.
    Garantiza que todos los módulos guarden los TXT en la carpeta de resultados.
    """
    try:
        # Obtener ruta base desde la configuración global
        base = config.HISTORIAL_RUTAS.get('path', os.getcwd())
        folder = config.HISTORIAL_RUTAS.get('folder', 'Resultados_General')
        full_dir = os.path.join(base, folder)
        
        # Crear la carpeta si no existe
        if not os.path.exists(full_dir):
            os.makedirs(full_dir, exist_ok=True)
            
        return os.path.join(full_dir, nombre_archivo)
    except:
        # Fallback en caso de error extremo
        return os.path.abspath(nombre_archivo)
        
# =============================================================================
# GENERADOR DE REPORTES HTML (Dashboard en tiempo real)
# =============================================================================
def generar_reporte_html(out_f, cfg=None):
    """
    Genera el Dashboard HTML y los reportes individuales.
    MODIFICADO: Ahora incluye botones de navegación entre reportes.
    """
    # 1. Asegurar ruta de salida
    if not out_f:
        try: out_f = os.path.join(config.HISTORIAL_RUTAS['path'], config.HISTORIAL_RUTAS['folder'])
        except: out_f = os.getcwd()

    if not os.path.exists(out_f):
        try: os.makedirs(out_f)
        except: return

    # 2. Definir Estilos CSS (Incluye nuevos botones de navegación)
    css = """<style>
        body{background-color:#090011;color:#f3e5f5;font-family:'Consolas',monospace;padding:20px}
        h1,h2{color:#d500f9;text-align:center;text-transform:uppercase;letter-spacing:2px;text-shadow:0 0 10px #d500f9}
        .card{border:1px solid #4a148c;background:#1a0526;margin:10px;padding:15px;border-left:5px solid #d500f9;box-shadow:0 0 10px rgba(74,20,140,0.4);transition:transform 0.2s; width: 280px; display:inline-block; vertical-align:top;}
        .card:hover{transform:scale(1.02);box-shadow:0 0 20px rgba(213,0,249,0.6)}
        .status-danger{border-left-color: #ff1744 !important; box-shadow: 0 0 10px rgba(255, 23, 68, 0.4);}
        .status-clean{border-left-color: #00e676 !important;}
        .status-pending{border-left-color: #757575 !important; opacity: 0.7;}
        pre{white-space:pre-wrap;word-wrap:break-word;background:#0f0018;padding:15px;border:1px solid #6a1b9a;color:#e1bee7;font-size:0.8em; max-height: 60vh; overflow-y: auto;}
        
        /* BARRA DE NAVEGACIÓN */
        .nav-bar {display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding: 10px; background: #1a0526; border: 1px solid #4a148c; border-radius: 50px;}
        .nav-btn {text-decoration: none; color: #ea80fc; font-weight: bold; padding: 8px 20px; border: 1px solid #d500f9; border-radius: 20px; transition: 0.3s;}
        .nav-btn:hover {background: #d500f9; color: #090011;}
        .nav-btn.disabled {opacity: 0.3; cursor: default; border-color: #555; color: #555;}
        .nav-btn.disabled:hover {background: transparent; color: #555;}
        .dash-btn {font-size: 1.1em; letter-spacing: 1px;}

        .footer{text-align:center;margin-top:50px;color:#7b1fa2;font-size:0.8em; clear:both;}
        .timestamp{color:#9c27b0;font-size:0.9em;text-align:center;margin-bottom:30px}
        .badge {padding: 2px 8px; border-radius: 4px; font-size: 0.8em; color: black; font-weight: bold;}
        .b-danger {background: #ff1744; color: white;}
        .b-clean {background: #00e676;}
        .b-pending {background: #757575; color: white;}
    </style>"""

    # 3. Mapa de Fases
    fmap = {
        'f1':("ShimCache","Shimcache_Rastros.txt"), 'f2':("AppCompat","rastro_appcompat.txt"), 
        'f3':("Identity","cambios_sospechosos.txt"), 'f4':("Signatures","Digital_Signatures_ZeroTrust.txt"), 
        'f5':("Keywords","buscar_en_disco.txt"), 'f6':("Hidden","archivos_ocultos.txt"), 
        'f7':("MFT_ADS","MFT_Archivos.txt"), 'f8':("UserAssist","UserAssist_Decoded.txt"), 
        'f9':("USB","USB_History.txt"), 'f10':("DNS","DNS_Cache.txt"), 
        'f11':("Browser","Browser_Forensics.txt"), 'f12':("Persistence","Persistence_Check.txt"), 
        'f13':("Events","Windows_Events.txt"), 'f14':("ProcessHunter","Process_Hunter.txt"), 
        'f15':("GameCheats","Game_Cheat_Hunter.txt"), 'f16':("NuclearTraces","Nuclear_Traces.txt"), 
        'f17':("KernelHunter","Kernel_Anomalies.txt"), 'f18':("DNA_Prefetch","DNA_Prefetch.txt"), 
        'f19':("NetworkHunter","Network_Anomalies.txt"), 'f20':("ToxicLNK","Toxic_LNK.txt"), 
        'f21':("GhostTrails","Ghost_Trails.txt"), 'f22':("MemoryScanner","Memory_Injection_Report.txt"), 
        'f23':("RogueDrivers","Rogue_Drivers.txt"), 'f24':("DeepStatic","Deep_Static_Analysis.txt"), 
        'f25':("Metamorphosis","Metamorphosis_Report.txt"),'f26':("StringCleaner","String_Cleaner_Detection.txt"),
        'vt':("VirusTotal","detecciones_virustotal.txt")
    }

    # 4. RECOLECCIÓN: Primero reunimos todos los datos de los reportes activos
    active_reports = []
    
    for k, (tit, arch) in fmap.items():
        tp = os.path.join(out_f, arch)
        file_exists = os.path.exists(tp)
        
        should_show = False
        if file_exists: should_show = True
        elif cfg and k == 'vt' and cfg.get('vt', {}).get('active'): should_show = True
        elif cfg and k in cfg and cfg[k].get('active'): should_show = True

        if should_show:
            hf = f"{k}_{arch.replace('.txt','.html')}" # Nombre archivo HTML
            
            c_h = ""; status = "PENDING"; card_class = "status-pending"; badge = "<span class='badge b-pending'>WAITING</span>"; meta_refresh = "<meta http-equiv='refresh' content='3'>"
            
            if file_exists:
                try:
                    with open(tp, "r", encoding="utf-8", errors="ignore") as f: raw_content = f.read()
                    if len(raw_content) > 10: 
                        safe_content = html.escape(raw_content)
                        safe_content = safe_content.replace("[!!!]", "<span style='color:#ff1744; background:#330000; padding:2px; font-weight:bold;'>[!!!]</span>")
                        safe_content = safe_content.replace("[ALERTA]", "<span style='color:#ffea00; font-weight:bold;'>[ALERTA]</span>")
                        c_h = f"<pre>{safe_content}</pre>"; meta_refresh = ""
                        
                        if "[!!!]" in raw_content or "DETECTED" in raw_content or "THREAT" in raw_content or "MALICIOUS" in raw_content:
                            status = "THREAT"; card_class = "status-danger"; badge = "<span class='badge b-danger'>THREAT FOUND</span>"
                        else:
                            status = "CLEAN"; card_class = "status-clean"; badge = "<span class='badge b-clean'>CLEAN</span>"
                    else: c_h = "<p style='color:gray'>Initializing log...</p>"
                except Exception as e: c_h = f"<p style='color:red'>Error reading log: {e}</p>"
            else: c_h = "<p style='color:gray; animation: blink 1s infinite;'>Scanning in progress...</p><style>@keyframes blink{50%{opacity:0.5}}</style>"
            
            # Guardamos todos los datos necesarios para generar el HTML más tarde
            active_reports.append({
                'title': tit,
                'html_filename': hf,
                'content': c_h,
                'badge': badge,
                'status': status,
                'card_class': card_class,
                'meta': meta_refresh,
                'file_path': os.path.join(out_f, hf)
            })

    # 5. GENERACIÓN: Creamos los HTMLs individuales con los enlaces calculados
    count = len(active_reports)
    for i, report in enumerate(active_reports):
        # Calcular enlaces
        prev_link = active_reports[i-1]['html_filename'] if i > 0 else None
        next_link = active_reports[i+1]['html_filename'] if i < count - 1 else None
        
        # HTML de la barra de navegación
        nav_html = '<div class="nav-bar">'
        if prev_link: nav_html += f'<a href="{prev_link}" class="nav-btn">&lt; PREV</a>'
        else: nav_html += '<span class="nav-btn disabled">&lt; PREV</span>'
        
        nav_html += '<a href="index.html" class="nav-btn dash-btn">DASHBOARD</a>'
        
        if next_link: nav_html += f'<a href="{next_link}" class="nav-btn">NEXT &gt;</a>'
        else: nav_html += '<span class="nav-btn disabled">NEXT &gt;</span>'
        nav_html += '</div>'

        # Contenido completo de la página
        page_content = f"""<!DOCTYPE html>
        <html>
        <head><title>{report['title']}</title>{css}{report['meta']}</head>
        <body>
            {nav_html}
            <h1>{report['title']} <small>{report['badge']}</small></h1>
            <div class='card' style='width: 95%; border-left: 5px solid {('#ff1744' if report['status']=='THREAT' else '#d500f9')}'>
                {report['content']}
            </div>
            <div class='footer'>SCANNELER V80 | FORENSIC MODULE</div>
        </body>
        </html>"""
        
        try:
            with open(report['file_path'], "w", encoding="utf-8") as f: f.write(page_content)
        except: pass

    # 6. GENERACIÓN DEL DASHBOARD (INDEX)
    if active_reports:
        dbh = f"<!DOCTYPE html><html><head><title>SCANNELER DASHBOARD</title>{css}<meta http-equiv='refresh' content='4'></head><body><h1>SCANNELER <span style='color:#d500f9'>|</span> LIVE MONITOR</h1><div class='timestamp'>SYSTEM TIME: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div><div style='display:flex;flex-wrap:wrap;justify-content:center;'>"
        for r in active_reports: 
            dbh += f"<div class='card {r['card_class']}'><h3>{r['title']}</h3><div style='margin:10px 0;'>{r['badge']}</div><p><a href='{r['html_filename']}' style='display:block; background:#000; padding:5px; text-align:center;'>OPEN REPORT &gt;</a></p></div>"
        dbh += "</div><div class='footer'>JELER33 PRIVATE TOOL | END OF LINE</div></body></html>"
        try:
            with open(os.path.join(out_f, "index.html"), "w", encoding="utf-8") as f: f.write(dbh)
        except: pass


# =============================================================================
# CLASE DE CONTEXTO OPTIMIZADO (SNAPSHOT)
# =============================================================================
class ScannerContext:
    def __init__(self):
        self.file_snapshot = [] 
        self.process_snapshot = []
        self.is_ready = False

    def prepare(self, status_callback=None):
        if status_callback: status_callback("Indexing Processes in RAM...")
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
                try: self.process_snapshot.append(proc.info)
                except: pass
        except: pass

        if status_callback: status_callback("Indexing File System (Smart Scan)...")
        user = os.environ.get("USERPROFILE", "C:\\")
        hot_paths = [
            os.path.join(user, "Downloads"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "AppData", "Local", "Temp"),
            os.path.join(user, "AppData", "Roaming")
        ]
        
        IGNORED_FOLDERS = {
            "node_modules", ".git", ".vs", "cache", "cachedata", "logs", 
            "steamapps", "riot games", "epic games", "call of duty", "warzone",
            "microsoft", "windows", "google", "brave-browser", "edge", "mozilla",
            "nvidia", "amd", "intel", "common files", "program files", "servicing", "assembly"
        }
        
        count = 0
        for base_path in hot_paths:
            if not os.path.exists(base_path): continue
            for root, dirs, files in os.walk(base_path):
                if config.CANCELAR_ESCANEO: return
                dirs[:] = [d for d in dirs if d.lower() not in IGNORED_FOLDERS and not d.startswith('.')]
                for name in files:
                    try:
                        count += 1
                        if count % 1000 == 0 and status_callback:
                            status_callback(f"Indexing Files... ({count})")
                        fp = os.path.join(root, name)
                        ext = os.path.splitext(name)[1].lower()
                        is_hidden = False
                        try:
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(fp)
                            if attrs != -1 and (attrs & 2): is_hidden = True
                        except: pass
                        sz = 0
                        try: sz = os.path.getsize(fp)
                        except: pass
                        self.file_snapshot.append({'path': fp, 'name': name.lower(), 'ext': ext, 'size': sz, 'hidden': is_hidden})
                    except: pass
        self.is_ready = True
        if status_callback: status_callback("Snapshot Ready. Starting Modules...")

# =============================================================================
# FASES DE ESCANEO
# =============================================================================

def fase_shimcache(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    
    config.reporte_shim = asegurar_ruta_reporte("Shimcache_Rastros.txt")
    print(f"[F1] ShimCache Nuclear: Timeline Sorting (Newest First)...")

    # 1. Mapeo de Discos
    discos_usb = []
    try:
        import psutil
        partitions = psutil.disk_partitions(all=True)
        for p in partitions:
            if 'removable' in p.opts or 'cdrom' in p.opts:
                discos_usb.append(p.device[:2].upper())
    except: pass 

    # 2. Extracción Raw (Registry)
    raw_paths = []
    try:
        reg_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        data, type_ = winreg.QueryValueEx(key, "AppCompatCache")
        winreg.CloseKey(key)

        import struct
        
        if len(data) > 52 and data[0:4] == b'10ts': # Win 10/11
            pos = 52 
            while pos < len(data) - 10:
                try:
                    if data[pos:pos+4] != b'10ts':
                        pos += 1
                        continue
                    
                    entry_size = struct.unpack('<I', data[pos+8:pos+12])[0]
                    path_len = struct.unpack('<H', data[pos+12:pos+14])[0]
                    
                    if entry_size == 0: 
                        pos += 4
                        continue

                    path_bytes = data[pos+14 : pos+14+path_len]
                    path_str = path_bytes.decode('utf-16-le', errors='ignore').strip('\x00')
                    
                    if path_str and "System32" not in path_str:
                        raw_paths.append(path_str)
                    
                    pos += entry_size
                except: pos += 1
        else: # Legacy
            text_data = data.decode('utf-16-le', errors='ignore')
            import re
            found = re.findall(r'[a-zA-Z]:\\[a-zA-Z0-9_\\\-\. ]+\.exe', text_data, re.IGNORECASE)
            raw_paths = list(found)

    except Exception as e:
        print(f"Error parsing Registry: {e}")

    # 3. PROCESAMIENTO Y ORDENAMIENTO POR FECHA REAL
    processed_entries = []
    
    # Whitelist
    SAFE_PATHS = [
        r"\windows\system32", r"\windows\syswow64", r"\windows\servicing", 
        r"\program files\google", r"\program files (x86)\google",
        r"\program files\windows defender", r"\program files\microsoft",
        r"\program files\nvidia", r"\program files\amd", r"\program files\intel",
        r"\program files\java", r"\program files\common files",
        r"\program files\git", r"\program files\docker", r"\program files\vscode",
        r"\appdata\local\programs\python", r"\appdata\local\programs\microsoft vs code"
    ]
    SAFE_NAMES = ["setup.exe", "install.exe", "update.exe", "mpsigstub.exe", "unins000.exe"]

    for path in raw_paths:
        path = path.strip()
        if len(path) < 3: continue
        
        path_lower = path.lower()
        name = os.path.basename(path_lower)
        
        # Filtros de Ruido
        if any(s in path_lower for s in SAFE_PATHS): continue
        if ("\\temp\\" in path_lower or "softwaredistribution" in path_lower) and name in SAFE_NAMES: continue

        # Obtener Fecha del Sistema de Archivos
        timestamp = 0
        date_display = "GHOST / DELETED"
        exists = os.path.exists(path)
        
        if exists:
            try:
                timestamp = os.path.getmtime(path)
                date_display = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except: 
                pass
        
        # Guardar objeto para ordenar después
        processed_entries.append({
            'path': path,
            'ts': timestamp,
            'date': date_display,
            'exists': exists,
            'name': name,
            'drive': path[:2].upper()
        })

    # --- ORDENAMIENTO CRÍTICO: De Mayor Timestamp (Reciente) a Menor (Antiguo) ---
    # Los archivos borrados (ts=0) quedarán al final
    processed_entries.sort(key=lambda x: x['ts'], reverse=True)

    # 4. ANÁLISIS DE AMENAZAS Y ESCRITURA
    with open(config.reporte_shim, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== SHIMCACHE TIMELINE (SORTED BY DATE) ===\n")
        f.write(f"Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'MODIFIED DATE':<20} | {'STATUS':<25} | PATH\n")
        f.write("-" * 110 + "\n")

        count_threats = 0

        for entry in processed_entries:
            path = entry['path']
            tags = []
            is_suspicious = False
            
            # Criterios
            if entry['drive'] in discos_usb:
                tags.append("USB-EXEC")
                is_suspicious = True
            
            if any(p in entry['name'] for p in palabras):
                tags.append("KEYWORD")
                is_suspicious = True
            
            if modo == "Analizar Todo":
                is_suspicious = True

            # Verificación Forense
            status_text = "CLEAN"
            
            if is_suspicious:
                if entry['exists']:
                    # Verificar Firma
                    try:
                        valid_sig, msg = verificar_firma_nativa(path)
                        if valid_sig:
                            # Si está firmado y no es USB, reducir ruido
                            if "USB-EXEC" not in tags: continue
                            status_text = "[SIGNED] USB"
                        else:
                            tags.append("UNSIGNED")
                            status_text = f"[!!!] {' '.join(tags)}"
                            count_threats += 1
                    except: pass
                else:
                    # Borrado
                    if "KEYWORD" in tags or "USB-EXEC" in tags or modo == "Analizar Todo":
                        tags.append("DELETED")
                        status_text = f"[!!!] {' '.join(tags)}"
                        count_threats += 1
                    else:
                        continue # Ignorar borrados genéricos no sospechosos

            # Escribir fila ordenada
            f.write(f"{entry['date']:<20} | {status_text:<25} | {path}\n")

        if count_threats == 0:
            f.write("\n[OK] No high-risk anomalies found in execution history.\n")

    try: generar_reporte_html(os.path.dirname(config.reporte_shim), {'f1': {'active': True}})
    except: pass
    
def fase_rastro_appcompat(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    objetivos = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "COMPATIBILITY STORE (USER)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "COMPATIBILITY STORE (SYSTEM)"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "COMPATIBILITY LAYERS (USER)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "COMPATIBILITY LAYERS (SYSTEM)")
    ]

    # Forzar ruta si no existe
    if not config.reporte_appcompat: config.reporte_appcompat = "AppCompat.txt"

    with open(config.reporte_appcompat, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== APPCOMPAT & GHOST TRACES: {datetime.datetime.now()} ===\n")
        hits = 0
        for hkey, subkey, titulo in objetivos:
            f.write(f"--- ANALIZANDO: {titulo} ---\n")
            try:
                with winreg.OpenKey(hkey, subkey) as k:
                    info_key = winreg.QueryInfoKey(k)
                    num_values = info_key[1]
                    for i in range(num_values):
                        try:
                            n, d, _ = winreg.EnumValue(k, i)
                            ruta_limpia = n.replace(r"\\?\/", "").replace(r"\\??\\", "")
                            nombre_archivo = os.path.basename(ruta_limpia).lower()
                            existe = os.path.exists(ruta_limpia)
                            es_sospechoso = False
                            etiqueta = "[INFO]"
                            
                            if any(p in nombre_archivo for p in palabras):
                                es_sospechoso = True
                                etiqueta = "[ALERTA] KEYWORD MATCH"

                            carpetas_calientes = ["downloads", "temp", "appdata", "desktop"]
                            if not existe and any(c in ruta_limpia.lower() for c in carpetas_calientes):
                                if "update" not in nombre_archivo and "install" not in nombre_archivo:
                                    if es_sospechoso: etiqueta = "[!!!] DELETED CHEAT TRACE"
                                    else: etiqueta = "[WARN] GHOST FILE (DELETED)"
                                    if modo == "Analizar Todo": es_sospechoso = True

                            if "LAYERS" in titulo:
                                flags = str(d).upper()
                                if "RUNASADMIN" in flags or "HIGHEST" in flags:
                                    if es_sospechoso: etiqueta += " + ADMIN RIGHTS"
                                    else: etiqueta += " (RunAsAdmin)"

                            if es_sospechoso or modo == "Analizar Todo":
                                estado_archivo = "(FILE EXISTS)" if existe else "(FILE DELETED/MOVED)"
                                f.write(f" {etiqueta} {ruta_limpia}\n")
                                f.write(f"      Status: {estado_archivo}\n")
                                if "LAYERS" in titulo: f.write(f"      Flags: {d}\n")
                                f.write("-" * 40 + "\n")
                                hits += 1
                                f.flush()
                        except Exception: continue
            except Exception as e:
                f.write(f" [ERROR] Accessing key {titulo}: {e}\n")
            f.write("\n")
        if hits == 0:
            f.write("[OK] No suspicious execution traces found in AppCompat.\n")
    
    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_appcompat)), {'f2': {'active': True}})
    except: pass

# --- F3: IDENTITY CHECK (OPTIMIZADA) ---
def fase_nombre_original(context, palabras, vt, modo):
    """OPTIMIZADA: Usa context.process_snapshot en vez de wmic"""
    if config.CANCELAR_ESCANEO: return
    print(f"[3/25] Identity Analysis (Multi-Threaded Nuclear) [MAX SPEED]...")
    
    # Asegurar ruta del reporte
    if not config.reporte_sospechosos: 
        base = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        fold = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
        config.reporte_sospechosos = os.path.join(base, fold, "cambios_sospechosos.txt")

    detections = []
    
    # Usar snapshot en memoria (instantáneo)
    for proc in context.process_snapshot:
        try:
            exe_path = proc.get('exe')
            if not exe_path or not os.path.exists(exe_path): continue
            
            # Optimización: Solo analizar si el nombre coincide con palabras clave o modo total
            proc_name_lower = (proc.get('name') or "").lower()
            should_scan = modo == "Analizar Todo" or any(p in proc_name_lower for p in palabras)
            if not should_scan: continue

            pe = pefile.PE(exe_path, fast_load=True)
            original_name = None
            if hasattr(pe, 'FileInfo'):
                for info in pe.FileInfo:
                    if hasattr(info, 'StringTable'):
                        for st in info.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode('utf-8','ignore').replace('\x00','')
                                if key in ['OriginalFilename', 'InternalName']:
                                    val = v.decode('utf-8','ignore').replace('\x00','').lower()
                                    if val.endswith(".exe"): 
                                        original_name = val
                                        break
                            if original_name: break
                    if original_name: break
            pe.close()
            
            if original_name:
                real = original_name.replace(".exe", "").strip()
                actual = proc_name_lower.replace(".exe", "").strip()
                whitelist = ["setup", "install", "update", "unity", "unins", "launch", "dota", "csgo"]
                # Detectar discrepancia
                if real != actual and real not in actual and actual not in real:
                    if not any(w in real for w in whitelist):
                        detections.append((exe_path, actual, real))
        except: pass

    # Escribir reporte
    with open(config.reporte_sospechosos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== ANALISIS IDENTIDAD (OPTIMIZED MEMORY SCAN): {datetime.datetime.now()} ===\n\n")
        if detections:
            for ruta, actual, real in detections:
                f.write(f"[!!!] FAKE NAME DETECTED:\n")
                f.write(f"      File on Disk: {actual}\n")
                f.write(f"      Real Name (PE): {real}\n")
                f.write(f"      Path: {ruta}\n")
                f.write("-" * 50 + "\n")
                if vt: cola_vt.put(ruta)
        else:
            f.write("No identity mismatches found in running processes.\n")
    
    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_sospechosos)), {'f3': {'active': True}})
    except: pass


# --- F4: FIRMAS DIGITALES ---
def verificar_firma_nativa(filepath):
    try:
        wintrust = ctypes.windll.wintrust
        # Estructuras WinAPI mínimas necesarias
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong), ("pcwszFilePath", ctypes.c_wchar_p), ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.c_void_p)]
        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", ctypes.c_ulong), ("dwPolicyCallbackData", ctypes.c_void_p), ("dwSIPClientData", ctypes.c_void_p), ("dwUIChoice", ctypes.c_ulong), ("fdwRevocationChecks", ctypes.c_ulong), ("dwUnionChoice", ctypes.c_ulong), ("pFile", ctypes.c_void_p), ("dwStateAction", ctypes.c_ulong), ("hWVTStateData", ctypes.c_void_p), ("pwszURLReference", ctypes.c_wchar_p), ("dwProvFlags", ctypes.c_ulong), ("dwUIContext", ctypes.c_ulong), ("pSignatureSettings", ctypes.c_void_p)]
        
        guid_bytes = uuid.UUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}').bytes_le
        p_guid = ctypes.create_string_buffer(guid_bytes)
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), filepath, None, None)
        trust_data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1, ctypes.pointer(file_info), 1, None, None, 0, 0, None)
        
        status = wintrust.WinVerifyTrust(None, p_guid, ctypes.byref(trust_data))
        trust_data.dwStateAction = 2 # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, p_guid, ctypes.byref(trust_data))
        
        if status == 0: return True, "VALID_TRUSTED"
        return False, f"INVALID_CODE_{hex(status)}"
    except Exception as e: return False, f"ERROR_API: {str(e)}"

def fase_verificar_firmas(context, palabras, vt, modo): # IMPORTANTE: 'context' en lugar de 'palabras' si se usa snapshot, o mantener args si gui.py lo manda así
    # NOTA: gui.py manda [context, palabras, vt, modo] para f4? Revisa gui.py.
    # Asumiendo argumentos estándar según tu gui.py
    if config.CANCELAR_ESCANEO: return
    print(f"[4/25] Digital Signature (Deep Recursive + Native API) [LETHAL SPEED]...")
    
    # Asegurar ruta
    if not config.reporte_firmas:
        base = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        fold = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
        config.reporte_firmas = os.path.join(base, fold, "Digital_Signatures_ZeroTrust.txt")
    
    target_exts = ('.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.ahk', '.lua', '.py', '.tmp')
    # Filtros para no escanear basura
    ignored_folders = {"node_modules", ".git", ".vs", "__pycache__", "vendor", "lib", "libs", "include", "steamapps", "riot games", "epic games", "ubisoft", "program files", "windows"}
    
    files_to_scan = set()
    user_profile = os.environ["USERPROFILE"]
    
    # Zonas de búsqueda profunda
    deep_zones = [
        os.path.join(user_profile, "Desktop"), 
        os.path.join(user_profile, "Downloads"), 
        os.path.join(user_profile, "AppData", "Local", "Temp"), 
        os.path.join(user_profile, "AppData", "Roaming")
    ]
    
    # Escaneo recursivo optimizado
    for zone in deep_zones:
        if not os.path.exists(zone): continue
        max_depth = 5 if "AppData" in zone else 10 
        root_depth = zone.count(os.sep)
        
        for root, dirs, files in os.walk(zone, topdown=True):
            if config.CANCELAR_ESCANEO: break
            # Poda de directorios
            dirs[:] = [d for d in dirs if d.lower() not in ignored_folders and not d.startswith('.')]
            
            current_depth = root.count(os.sep)
            if current_depth - root_depth > max_depth:
                del dirs[:]
                continue
                
            for name in files:
                if name.lower().endswith(target_exts):
                    full_path = os.path.join(root, name)
                    try:
                        # Limite de tamaño para no tardar años
                        if os.path.getsize(full_path) < 150 * 1024 * 1024:
                            files_to_scan.add(full_path)
                    except: pass

    scanned_count = 0
    unsigned_count = 0
    
    with open(config.reporte_firmas, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DIGITAL SIGNATURE DEEP SCAN: {datetime.datetime.now()} ===\n")
        f.write(f"Engine: Native WinVerifyTrust | Scope: Recursive (Smart Filter)\n")
        f.write(f"Targets Identified: {len(files_to_scan)}\n\n")
        
        for file_path in files_to_scan:
            if config.CANCELAR_ESCANEO: break
            scanned_count += 1
            is_valid, status_msg = verificar_firma_nativa(file_path)
            file_name = os.path.basename(file_path)
            
            if not is_valid:
                unsigned_count += 1
                f.write(f"[!!!] POTENTIAL THREAT (Unsigned): {file_name}\n")
                f.write(f"      Path: {file_path}\n")
                f.write(f"      Sign Status: {status_msg}\n")
                
                ext = os.path.splitext(file_name)[1].lower()
                if ext in ['.lua', '.ahk', '.py', '.bat']:
                    f.write(f"      Type: SCRIPT FILE (High Risk if hidden)\n")
                
                f.write("-" * 40 + "\n")
                f.flush()
                if vt: cola_vt.put(file_path)
            elif modo == "Analizar Todo":
                f.write(f"[OK] {file_name} [Signed]\n")
        
        f.write(f"\nScan Finished.\nTotal Files Checked: {scanned_count}\nUnsigned/Suspicious: {unsigned_count}")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_firmas)), {'f4': {'active': True}})
    except: pass

# --- F5: BUSCAR EN DISCO (OPTIMIZADA) ---
def fase_buscar_en_disco(context, kws, modo):
    if config.CANCELAR_ESCANEO: return
    
    # Asegurar ruta
    if not config.reporte_path: config.reporte_path = "Disk_Search.txt"
    
    hits = []
    # Usar snapshot en memoria (instantáneo)
    for f in context.file_snapshot:
        for p in kws:
            if p.lower() in f['name']:
                hits.append(f"Found: {f['path']} (Keyword: {p})")
                break
                
    with open(config.reporte_path, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DISK SEARCH (MEMORY SNAPSHOT): {datetime.datetime.now()} ===\n\n")
        if hits:
            f.write("\n".join(hits))
        else:
            f.write("No keywords found in hot paths.\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_path)), {'f5': {'active': True}})
    except: pass


# --- F6: ARCHIVOS OCULTOS (OPTIMIZADA) ---
def fase_archivos_ocultos(context, palabras, modo):
    if config.CANCELAR_ESCANEO: return
    
    # Asegurar ruta
    if not config.reporte_ocultos: config.reporte_ocultos = "Hidden_Files.txt"
    
    hits = []
    # Usar snapshot en memoria (instantáneo)
    for f in context.file_snapshot:
        if f['hidden']:
            name = f['name']
            path = f['path']
            tag = "[OCULTO]"
            
            # Clasificación de riesgo
            if name.endswith(('.exe', '.bat', '.ps1', '.vbs', '.dll', '.sys')): 
                tag = "[!!!] HIDDEN EXECUTABLE"
            elif any(p in name for p in palabras): 
                tag = "[ALERTA] KEYWORD HIDDEN"
            
            hits.append(f"{tag}: {path}")

    with open(config.reporte_ocultos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== HIDDEN FILES (MEMORY SNAPSHOT): {datetime.datetime.now()} ===\n\n")
        if hits:
            f.write("\n".join(hits))
        else:
            f.write("No hidden files found in hot paths.\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_ocultos)), {'f6': {'active': True}})
    except: pass
    
    
# --- F7: MFT & ADS ---
def fase_mft_ads(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[7/25] MFT & ADS Hunter (Native Speed) [LETHAL]...")
    
    # Asegurar ruta
    if not config.reporte_mft: config.reporte_mft = "MFT_ADS.txt"
    
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]
    kernel32 = ctypes.windll.kernel32
    FindFirstStreamW = kernel32.FindFirstStreamW
    FindNextStreamW = kernel32.FindNextStreamW
    FindClose = kernel32.FindClose
    
    user_profile = os.environ['USERPROFILE']
    targets = [os.path.join(user_profile, "Downloads"), os.path.join(user_profile, "Desktop"), os.path.join(user_profile, "AppData", "Local", "Temp")]

    with open(config.reporte_mft, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== ADS & ORIGIN HUNTER (NATIVE): {datetime.datetime.now()} ===\n\n")
        for target_dir in targets:
            if not os.path.exists(target_dir): continue
            for root, _, files in os.walk(target_dir):
                if config.CANCELAR_ESCANEO: break
                for file in files:
                    full_path = os.path.join(root, file)
                    find_data = WIN32_FIND_STREAM_DATA()
                    h_find = FindFirstStreamW(full_path, 0, ctypes.byref(find_data), 0)
                    if h_find != -1:
                        try:
                            while True:
                                stream_name = find_data.cStreamName
                                if stream_name and stream_name != "::$DATA":
                                    real_stream = stream_name.split(":")[1]
                                    if real_stream == "Zone.Identifier":
                                        try:
                                            with open(f"{full_path}:{real_stream}", "r", errors="ignore") as ads_f:
                                                content = ads_f.read()
                                                if "HostUrl=" in content:
                                                    url = content.split("HostUrl=")[1].splitlines()[0].strip()
                                                    bad_domains = ["discord", "anonfiles", "mega.nz", "gofile", "cheats", "unknowncheats", "github"]
                                                    if any(b in url.lower() for b in bad_domains) or modo == "Analizar Todo":
                                                        tag = "[!!!] SUSPICIOUS SOURCE" if any(b in url.lower() for b in bad_domains) else "[INFO]"
                                                        f.write(f"{tag} File: {file}\n")
                                                        f.write(f"      Origin: {url}\n")
                                                        f.write("-" * 40 + "\n")
                                        except: pass
                                    elif real_stream not in ["favicon", "smartscreen"]:
                                        f.write(f"[!!!] HIDDEN PAYLOAD DETECTED: {file}\n")
                                        f.write(f"      Stream Name: {real_stream}\n")
                                        f.write(f"      Size: {find_data.StreamSize} bytes\n")
                                        f.write("-" * 40 + "\n")
                                if not FindNextStreamW(h_find, ctypes.byref(find_data)): break
                        finally: FindClose(h_find)
    
    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_mft)), {'f7': {'active': True}})
    except: pass


# --- F8: USERASSIST ---
def fase_userassist(palabras, modo):
    print("[28/28] UserAssist (Human Interaction + Timestamps)...")
    
    # Asegurar ruta
    if not config.reporte_userassist: 
        try:
            base_path = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
            folder_name = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
        except:
            base_path = os.path.abspath(".")
            folder_name = "Resultados_SS"
        config.reporte_userassist = os.path.join(base_path, folder_name, "User_Interaction_Trace.txt")

    def parse_userassist_data(binary_data):
        try:
            run_count = 0
            last_run_str = "Unknown"
            if len(binary_data) >= 8:
                run_count = struct.unpack('<I', binary_data[4:8])[0]
            if len(binary_data) >= 68:
                ft = struct.unpack('<Q', binary_data[60:68])[0]
                if ft > 0:
                    us = ft / 10
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
                    last_run_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    return run_count, last_run_str, dt
            return run_count, last_run_str, None
        except: return 0, "Error Parsing", None

    limit_date = datetime.datetime.now() - datetime.timedelta(days=5)
    
    with open(config.reporte_userassist, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USERASSIST FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Evidence of GUI Execution, Run Counts, and Deleted Files.\n\n")
        hits = 0
        try:
            r = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r) as k_ua:
                num_subkeys = winreg.QueryInfoKey(k_ua)[0]
                for i in range(num_subkeys):
                    guid = winreg.EnumKey(k_ua, i)
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{r}\\{guid}\\Count") as k_c:
                            num_values = winreg.QueryInfoKey(k_c)[1]
                            for j in range(num_values):
                                n_rot, data, type_ = winreg.EnumValue(k_c, j)
                                try:
                                    n_real = codecs.decode(n_rot, 'rot_13')
                                    if "}" in n_real: n_real = n_real.split("}")[-1]
                                    else: clean_path = n_real
                                    clean_path = n_real
                                    if ":" not in clean_path and not clean_path.startswith("\\"): continue 
                                    count, last_run, dt_obj = parse_userassist_data(data)
                                    es_sospechoso = False
                                    tag = "[INFO]"
                                    if any(p in clean_path.lower() for p in palabras):
                                        tag = "[ALERTA] KEYWORD MATCH"
                                        es_sospechoso = True
                                    file_exists = os.path.exists(clean_path)
                                    if not file_exists and ("C:" in clean_path or "D:" in clean_path):
                                        if clean_path.lower().endswith(".exe") or clean_path.lower().endswith(".bat"):
                                            if es_sospechoso: tag = "[!!!] DELETED CHEAT EVIDENCE"
                                            else: tag = "[WARN] GHOST FILE (EXECUTED & DELETED)"
                                            if modo == "Analizar Todo" and dt_obj and dt_obj > limit_date: es_sospechoso = True
                                    if ("appdata" in clean_path.lower() or "temp" in clean_path.lower()) and clean_path.lower().endswith(".exe"):
                                        if not es_sospechoso and modo == "Analizar Todo":
                                            tag = "[SUSPICIOUS PATH]"
                                            es_sospechoso = True
                                    mostrar = False
                                    if es_sospechoso: mostrar = True
                                    elif modo == "Analizar Todo" and dt_obj and dt_obj > limit_date: mostrar = True
                                    if mostrar:
                                        status_str = "EXISTS" if file_exists else "DELETED/MISSING"
                                        f.write(f"[{last_run}] {tag}: {clean_path}\n")
                                        f.write(f"      Run Count: {count} times\n")
                                        f.write(f"      File Status: {status_str}\n")
                                        f.write("-" * 40 + "\n")
                                        f.flush()
                                        hits += 1
                                except Exception: continue
                    except Exception: continue
        except Exception as e: f.write(f"Error reading Registry: {e}\n")
        if hits == 0: f.write("[OK] No suspicious user interactions found in recent history.\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_userassist)), {'f8': {'active': True}})
    except: pass

# --- F9: USB HISTORY ---
def fase_usb_history(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[9/26] USB History & ShellBags (Devices + Folder Access) [LETHAL]")
    
    # Asegurar ruta
    if not config.reporte_usb: config.reporte_usb = "USB_History.txt"

    with open(config.reporte_usb, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USB EXECUTION & SHELLBAGS FORENSICS: {datetime.datetime.now()} ===\n")
        f.write("Target: Hardware Cheats, Removed Drives & Folder Access History.\n\n")
        
        discos_usb_activos = []
        discos_fijos = ["C:"] 
        try:
            cmd = "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType"
            proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            for line in out.splitlines():
                if "2" in line:
                    parts = line.split()
                    if parts: discos_usb_activos.append(parts[0])
                elif "3" in line or "4" in line:
                    parts = line.split()
                    if parts: discos_fijos.append(parts[0])
        except: pass
        f.write(f"[INFO] Active USB Drives: {', '.join(discos_usb_activos) if discos_usb_activos else 'None'}\n")
        f.write("-" * 60 + "\n\n")
        
        f.write("--- [1] HARDWARE ID SCAN (Arduinos & DMA) ---\n")
        bad_vids = {"2341": "ARDUINO", "16C0": "TEENSY", "1B4F": "SPARKFUN", "04D8": "MICROCHIP", "1A86": "CH340", "0403": "FTDI"}
        found_hw = False
        reg_path = r"SYSTEM\CurrentControlSet\Enum\USB"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                num_keys = winreg.QueryInfoKey(key)[0]
                for i in range(num_keys):
                    device_key_name = winreg.EnumKey(key, i)
                    threat_msg = ""
                    for vid, msg in bad_vids.items():
                        if f"VID_{vid}" in device_key_name.upper():
                            threat_msg = msg
                            break
                    if threat_msg or modo == "Analizar Todo":
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{device_key_name}") as subkey:
                                num_inst = winreg.QueryInfoKey(subkey)[0]
                                for j in range(num_inst):
                                    serial = winreg.EnumKey(subkey, j)
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{device_key_name}\\{serial}") as inst_key:
                                        try: name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                        except: 
                                            try: name, _ = winreg.QueryValueEx(inst_key, "DeviceDesc")
                                            except: name = "Unknown Device"
                                        try:
                                            ts_ns = winreg.QueryInfoKey(inst_key)[2]
                                            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts_ns/10)
                                            last_seen = dt.strftime('%Y-%m-%d %H:%M:%S')
                                        except: last_seen = "Unknown"
                                        
                                        if threat_msg:
                                            f.write(f"[!!!] HARDWARE CHEAT DETECTED: {threat_msg}\n")
                                            f.write(f"      Device: {name}\n")
                                            f.write(f"      HWID: {device_key_name}\n")
                                            f.write(f"      Last Connected: {last_seen}\n")
                                            f.write("-" * 40 + "\n")
                                            found_hw = True
                                        elif "MassStorage" in device_key_name or "DISK" in name.upper() or "USB" in name.upper():
                                             f.write(f"[HISTORY] {name} (Last: {last_seen})\n")
                        except: continue
        except Exception as e: f.write(f"Error scanning USB Registry: {e}\n")
        if not found_hw: f.write("[OK] No specific Hardware Cheat IDs found.\n")
        
        f.write("\n--- [2] EXECUTION FROM USB (UserAssist Evidence) ---\n")
        ua_hits = 0
        try:
            ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path) as k_ua:
                for i in range(winreg.QueryInfoKey(k_ua)[0]):
                    guid = winreg.EnumKey(k_ua, i)
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{ua_path}\\{guid}\\Count") as k_c:
                            for j in range(winreg.QueryInfoKey(k_c)[1]):
                                n_rot, data, _ = winreg.EnumValue(k_c, j)
                                n_real = codecs.decode(n_rot, 'rot_13')
                                if "}" in n_real: n_real = n_real.split("}")[-1]
                                if not n_real or ":" not in n_real: continue
                                drive_letter = n_real[:2].upper()
                                is_usb_exec = False
                                status_msg = ""
                                if drive_letter in discos_usb_activos:
                                    is_usb_exec = True
                                    status_msg = "ACTIVE USB"
                                elif drive_letter not in discos_fijos and drive_letter not in discos_usb_activos:
                                    if "X:" not in drive_letter and "Z:" not in drive_letter:
                                        is_usb_exec = True
                                        status_msg = "REMOVED DRIVE (GHOST)"
                                
                                if is_usb_exec:
                                    last_run = "Unknown"
                                    if len(data) >= 68:
                                        try:
                                            ft = struct.unpack('<Q', data[60:68])[0]
                                            if ft > 0:
                                                dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft/10)
                                                last_run = dt.strftime('%Y-%m-%d %H:%M:%S')
                                        except: pass
                                    
                                    if n_real.lower().endswith((".exe", ".bat", ".cmd", ".ps1")):
                                        tag = "[!!!]"
                                        if any(p in n_real.lower() for p in palabras): tag = "[!!!] CONFIRMED CHEAT"
                                        f.write(f"{tag} EXECUTION: {n_real}\n")
                                        f.write(f"      Status: {status_msg}\n")
                                        f.write(f"      Last Run: {last_run}\n")
                                        f.write("-" * 40 + "\n")
                                        ua_hits += 1
                    except: continue
        except Exception as e: f.write(f"Error reading UserAssist: {e}\n")
        if ua_hits == 0: f.write("[OK] No executable traces found directly from USB drives.\n")

        f.write("\n--- [3] SHORTCUTS TO REMOVED DRIVES (Ghost LNKs) ---\n")
        lnk_hits = 0
        ps_lnk_script = r"""
        $Recent = [Environment]::GetFolderPath("Recent")
        $WScript = New-Object -ComObject WScript.Shell
        Get-ChildItem $Recent -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $Target = $WScript.CreateShortcut($_.FullName).TargetPath
                if ($Target -match "^([A-Z]:)") {
                    $Drive = $Matches[1]
                    if ($Drive -ne "C:") { Write-Output "$($_.Name)|$Target|$Drive" }
                }
            } catch {}
        }
        """
        try:
            proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_lnk_script], stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            for line in out.splitlines():
                if "|" in line:
                    name, target, drive = line.split("|")
                    drive_status = "UNKNOWN"
                    if drive in discos_usb_activos: drive_status = "ACTIVE USB"
                    elif drive in discos_fijos: continue 
                    else: drive_status = "REMOVED/DISCONNECTED"
                    
                    if drive_status != "UNKNOWN":
                        tag = "[EVIDENCE]"
                        if drive_status == "REMOVED/DISCONNECTED": tag = "[!!!] GHOST LNK"
                        if any(p in target.lower() for p in palabras): tag = "[!!!] CHEAT LNK MATCH"
                        f.write(f"{tag} {name} -> {target}\n")
                        f.write(f"      Drive Status: {drive_status}\n")
                        lnk_hits += 1
        except: pass
        if lnk_hits == 0: f.write("[OK] No suspicious shortcuts to external drives found.\n")

        f.write("\n--- [4] SHELLBAGS (Folder Access History) ---\n")
        f.write("Detects specific folders opened by the user, even if the drive is gone.\n\n")
        folder_hits = 0
        KEYS_SHELLBAGS = [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU", r"Software\Microsoft\Windows\Shell\BagMRU"]
        
        def _extract_clean_strings(data):
            try:
                text = data.decode('utf-16-le', errors='ignore')
                return re.findall(r'[a-zA-Z0-9_\-\. \(\)\[\]]{4,}', text)
            except: return []
            
        def _walk_shellbags(key_path, hits_list):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    try:
                        i = 0
                        while True:
                            if config.CANCELAR_ESCANEO: break
                            _, val_data, val_type = winreg.EnumValue(key, i)
                            if val_type == winreg.REG_BINARY:
                                names = _extract_clean_strings(val_data)
                                for n in names:
                                    if len(n) < 3: continue
                                    if n.lower() in ["quick access", "this pc", "network", "recycle bin", "control panel", "documents", "pictures", "desktop", "downloads", "music", "videos"]: continue
                                    is_sus = False
                                    for p in palabras:
                                        if p.lower() in n.lower():
                                            is_sus = True
                                            break
                                    if is_sus: hits_list.append(n)
                            i += 1
                    except OSError: pass
                    
                    try:
                        j = 0
                        while True:
                            if config.CANCELAR_ESCANEO: break
                            subkey = winreg.EnumKey(key, j)
                            _walk_shellbags(f"{key_path}\\{subkey}", hits_list)
                            j += 1
                    except OSError: pass
            except: pass
            
        detected_folders = []
        for k in KEYS_SHELLBAGS:
            if config.CANCELAR_ESCANEO: break
            _walk_shellbags(k, detected_folders)
            
        detected_folders = list(set(detected_folders))
        if detected_folders:
            for folder in detected_folders:
                f.write(f"[!!!] SUSPICIOUS FOLDER ACCESSED: {folder}\n")
                folder_hits += 1
        else: f.write("[OK] No suspicious folder names found in ShellBags.\n")
        f.write(f"\nTotal USB/HW Anomalies: {ua_hits + lnk_hits + folder_hits + (1 if found_hw else 0)}\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_usb)), {'f9': {'active': True}})
    except: pass


# --- F10: DNS CACHE ---
def fase_dns_cache(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    
    try:
        subprocess.run("taskkill /IM discord.exe /F", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except: pass 
    
    discord_path = os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'leveldb')
    url_pattern = re.compile(rb'https?://(?:cdn|media)\.discordapp\.(?:com|net)/attachments/[\w\d_\-\./]+')
    
    # Asegurar ruta
    if not config.reporte_dns: config.reporte_dns = "DNS_Cache.txt"

    with open(config.reporte_dns, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== REPORTE DE RED Y ORIGEN (DNS + DISCORD): {datetime.datetime.now()} ===\n")
        f.write(f"\n[+] SECCIÓN DNS CACHE (Dominios Visitados)\n")
        f.write("="*60 + "\n")
        try:
            out = subprocess.check_output("ipconfig /displaydns", shell=True, text=True, errors='ignore')
            dns_encontrados = False
            for l in out.splitlines():
                l = l.strip()
                if "Nombre de registro" in l or "Record Name" in l:
                    parts = l.split(":")
                    if len(parts) > 1:
                        dom = parts[1].strip()
                        if dom and (modo == "Analizar Todo" or any(p in dom.lower() for p in palabras)):
                            f.write(f"  > DNS ENTRY: {dom}\n")
                            dns_encontrados = True
            if not dns_encontrados: f.write("  (Sin datos relevantes)\n")
        except Exception as e: f.write(f"  [ERROR] DNS: {str(e)}\n")
        
        f.write(f"\n\n[+] SECCIÓN DISCORD DOWNLOADS (Rastreo de Links)\n")
        f.write("="*60 + "\n")
        if os.path.exists(discord_path):
            links_encontrados = 0
            try: 
                for filename in os.listdir(discord_path):
                    if filename.endswith(".ldb") or filename.endswith(".log"):
                        full_path = os.path.join(discord_path, filename)
                        try:
                            with open(full_path, "rb") as db_file:
                                content = db_file.read()
                                matches = url_pattern.findall(content)
                                for url_bytes in matches:
                                    url_str = url_bytes.decode('utf-8', errors='ignore')
                                    es_sospechoso = False
                                    if any(ext in url_str.lower() for ext in ['.exe', '.dll', '.rar', '.zip', '.7z']): es_sospechoso = True
                                    elif modo != "Analizar Todo" and any(p in url_str.lower() for p in palabras): es_sospechoso = True
                                    elif modo == "Analizar Todo": es_sospechoso = True
                                    
                                    if es_sospechoso:
                                        f.write(f"  > LINK RECUPERADO: {url_str}\n")
                                        links_encontrados += 1
                        except: continue 
            except Exception as e: f.write(f"  [ERROR] Al leer carpeta Discord: {str(e)}\n")
            if links_encontrados == 0: f.write(f"  (No se encontraron enlaces sospechosos)\n")
        else: f.write("  [INFO] No se encontró carpeta de Discord.\n")
        f.flush()

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_dns)), {'f10': {'active': True}})
    except: pass

# --- F11: BROWSER FORENSICS ---
def fase_browser_forensics(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    
    # Asegurar ruta
    if not config.reporte_browser: config.reporte_browser = "Browser.txt"
    
    now = datetime.datetime.now()
    thirty_days_ago = now - datetime.timedelta(days=30)
    epoch_chromium = datetime.datetime(1601, 1, 1)
    limit_chromium = int((thirty_days_ago - epoch_chromium).total_seconds() * 1000000)
    epoch_firefox = datetime.datetime(1970, 1, 1)
    limit_firefox = int((thirty_days_ago - epoch_firefox).total_seconds() * 1000000)
    
    base_u = "C:\\Users"
    all_u = []
    if os.path.exists(base_u):
        for u_f in os.listdir(base_u):
            f_u_p = os.path.join(base_u, u_f)
            if os.path.isdir(f_u_p) and u_f.lower() not in ["public", "default", "default user", "all users"]: 
                all_u.append(f_u_p)
                
    b_cfg = { 
        "Chrome": {"r": r"AppData\Local\Google\Chrome\User Data", "t": "chromium"}, 
        "Edge": {"r": r"AppData\Local\Microsoft\Edge\User Data", "t": "chromium"}, 
        "Brave": {"r": r"AppData\Local\BraveSoftware\Brave-Browser\User Data", "t": "chromium"}, 
        "Opera": {"r": r"AppData\Roaming\Opera Software\Opera Stable", "t": "opera"}, 
        "Firefox": {"r": r"AppData\Roaming\Mozilla\Firefox\Profiles", "t": "firefox"} 
    }

    with open(config.reporte_browser, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== BROWSER FORENSICS (LAST 30 DAYS): {now} ===\n\n")
        
        for u_h in all_u:
            f.write(f"[[[ USER: {os.path.basename(u_h)} ]]]\n")
            
            for b_n, cfg in b_cfg.items():
                b_p = os.path.join(u_h, cfg["r"])
                b_t = cfg["t"]
                
                if not os.path.exists(b_p): continue
                
                profs = []
                if b_t == "chromium":
                    for i in os.listdir(b_p):
                        f_i = os.path.join(b_p, i)
                        if os.path.isdir(f_i) and (i=="Default" or "Profile" in i):
                            h_f = os.path.join(f_i, "History")
                            if os.path.exists(h_f): profs.append((i, h_f))
                elif b_t == "opera":
                    h_f = os.path.join(b_p, "History")
                    if os.path.exists(h_f): profs.append(("Default", h_f))
                elif b_t == "firefox":
                    for p in os.listdir(b_p):
                        pl_f = os.path.join(b_p, p, "places.sqlite")
                        if os.path.exists(pl_f): profs.append((p, pl_f))
                        
                for p_n, db_f in profs:
                    f.write(f"--- {b_n} [{p_n}] ---\n")
                    tmp_db = f"tmp_{random.randint(1000,9999)}.sqlite"
                    
                    try: shutil.copy2(db_f, tmp_db)
                    except:
                        try:
                            with open(db_f, "rb") as source, open(tmp_db, "wb") as dest: dest.write(source.read())
                        except: 
                            f.write(" [!] Locked/Access Denied\n")
                            continue
                            
                    try:
                        conn = sqlite3.connect(tmp_db)
                        cursor = conn.cursor()
                        
                        if b_t in ["chromium", "opera"]:
                            # --- HISTORY ---
                            try:
                                cursor.execute("SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC", (limit_chromium,))
                                for u, t, vt in cursor.fetchall():
                                    try: 
                                        dt = epoch_chromium + datetime.timedelta(microseconds=vt)
                                        fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except: fech = "Unknown"
                                    
                                    info = f"[HIST] [{fech}] {t} - {u}"
                                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): 
                                        f.write(f"{info}\n"); f.flush()
                            except: pass
                            
                            # --- DOWNLOADS ---
                            f.write("\n  > DOWNLOADS (Last 30 Days):\n")
                            rows_dl = []
                            try:
                                cursor.execute("SELECT target_path, start_time, tab_url, referrer FROM downloads WHERE start_time > ? ORDER BY start_time DESC", (limit_chromium,))
                                rows_dl = cursor.fetchall()
                            except: pass
                            
                            for p, st, t_url, ref in rows_dl:
                                try: 
                                    dt = epoch_chromium + datetime.timedelta(microseconds=st)
                                    fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                except: fech = "Unknown"
                                
                                info = f"  [DL] [{fech}] FILE: {p}\n       ORIGIN: {t_url if t_url else ref}"
                                if modo == "Analizar Todo" or any(k in info.lower() for k in palabras): 
                                    f.write(f"{info}\n"); f.flush()
                                    
                        elif b_t == "firefox":
                            try:
                                cursor.execute("SELECT P.url, P.title, H.visit_date FROM moz_places P, moz_historyvisits H WHERE P.id = H.place_id AND H.visit_date > ? ORDER BY H.visit_date DESC", (limit_firefox,))
                                for u, t, vd in cursor.fetchall():
                                    try: 
                                        dt = epoch_firefox + datetime.timedelta(microseconds=vd)
                                        fech = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    except: fech = "Unknown"
                                    
                                    info = f"[HIST] [{fech}] {t} - {u}"
                                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): 
                                        f.write(f"{info}\n"); f.flush()
                            except: pass
                            
                        conn.close()
                        os.remove(tmp_db)
                        f.write("\n")
                    except: 
                        if os.path.exists(tmp_db): 
                            try: os.remove(tmp_db)
                            except: pass
            f.write("\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_browser)), {'f11': {'active': True}})
    except: pass


# --- F12: PERSISTENCE ---
def fase_persistence(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    
    # Asegurar ruta
    if not config.reporte_persistencia: config.reporte_persistencia = "Persistence.txt"

    with open(config.reporte_persistencia, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== PERSISTENCE: {datetime.datetime.now()} ===\n\n")
        
        f.write("--- REGISTRY ---\n")
        r_reg = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), 
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"), 
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for h, s in r_reg:
            try:
                with winreg.OpenKey(h, s) as k:
                    for i in range(winreg.QueryInfoKey(k)[1]):
                        n, v, _ = winreg.EnumValue(k, i)
                        info = f"KEY: {n} -> {v}"
                        if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): 
                            f.write(f"[REG] {info}\n"); f.flush()
            except: pass
            
        f.write("\n--- STARTUP FOLDER ---\n")
        dirs = [
            os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup"), 
            os.path.join(os.getenv('PROGRAMDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")
        ]
        
        for d in dirs:
            if os.path.exists(d):
                for fl in os.listdir(d):
                    info = f"FILE: {fl} IN {d}"
                    if modo == "Analizar Todo" or any(p in info.lower() for p in palabras): 
                        f.write(f"[DIR] {info}\n"); f.flush()
                        
        f.write("\n--- TASKS ---\n")
        try:
            proc = subprocess.Popen('schtasks /query /fo LIST /v', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True, text=True)
            out, _ = proc.communicate()
            t_n = ""
            for l in out.splitlines():
                if "TaskName:" in l or "Nombre de tarea:" in l: t_n = l.strip()
                if "Task To Run:" in l or "Tarea para ejecutar:" in l:
                    t_r = l.strip()
                    full = f"{t_n} | {t_r}"
                    if "Microsoft\\" not in t_n and (modo == "Analizar Todo" or any(p in full.lower() for p in palabras)): 
                        f.write(f"[TASK] {full}\n"); f.flush()
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_persistencia)), {'f12': {'active': True}})
    except: pass

def fase_event_logs(palabras, modo):
    """
    FASE 13: WINDOWS DEFENDER & USN JOURNAL (UNIVERSAL PARSER)
    - [1] ACTIVAS: Estado actual.
    - [2] QUITADAS: VSS.
    - [3] USN JOURNAL: Extracción basada en posición relativa a la FECHA.
    """
    if config.CANCELAR_ESCANEO: return

    print(f"[13/26] Windows Defender & USN Journal (Universal Audit)...")

    if not config.reporte_eventos: config.reporte_eventos = "Events_Forensics.txt"

    # =========================================================================
    # POWERSHELL SCRIPT
    # =========================================================================
    ps_command = r"""
    $ErrorActionPreference = "SilentlyContinue"
    $Results = @()

    # --- 1. ACTIVAS ---
    $Current = Get-MpPreference
    $ActivePaths = if ($Current.ExclusionPath) { @($Current.ExclusionPath) } else { @() }
    $ActiveProcs = if ($Current.ExclusionProcess) { @($Current.ExclusionProcess) } else { @() }
    $Results += @{ Type="ACTIVE"; Data=@{ Paths=$ActivePaths; Procs=$ActiveProcs } }

    # --- 2. VSS (QUITADAS) ---
    $Shadow = Get-WmiObject Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1
    if ($Shadow) {
        $ShadowDate = $Shadow.InstallDate
        $DevicePath = $Shadow.DeviceObject
        $MountName = "DEFENDER_VSS_TEMP"
        reg unload "HKLM\$MountName" 2>$null | Out-Null
        reg load "HKLM\$MountName" "$DevicePath\Windows\System32\config\SOFTWARE" 2>$null | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            $VSS_Base = "HKLM:\$MountName\Microsoft\Windows Defender\Exclusions"
            $Deleted = @()
            if (Test-Path "$VSS_Base\Paths") {
                Get-ItemProperty -Path "$VSS_Base\Paths" | Select-Object * -ExcludeProperty "PS*" | ForEach-Object {
                    $_.PSObject.Properties | ForEach-Object {
                        if ($_.Name -notin $ActivePaths) { 
                            $Deleted += @{ Target=$_.Name; Category="PATH"; FoundIn=$ShadowDate } 
                        }
                    }
                }
            }
            $Results += @{ Type="DELETED_VSS"; Data=$Deleted }
            [gc]::Collect()
            reg unload "HKLM\$MountName" 2>$null | Out-Null
        }
    }

    # --- 3. USN JOURNAL (PARSEO RELATIVO A FECHA) ---
    try {
        # Traemos los últimos 200 eventos crudos
        $USN_Raw = fsutil usn readjournal C: csv | Select-Object -Last 200
        
        $JournalEvents = @()

        foreach ($Line in $USN_Raw) {
            $LineStr = $Line.ToString()
            
            # 1. ENCONTRAR LA FECHA (El ancla)
            # Buscamos el patrón "dd/mm/yyyy hh:mm:ss" (con o sin comillas)
            # Regex: \d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}
            
            if ($LineStr -match "(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})") {
                $FullDate = $Matches[1]
                
                # 2. SEPARAR LO QUE HAY ANTES Y DESPUÉS DE LA FECHA
                $SplitParts = $LineStr -split [regex]::Escape($FullDate)
                
                if ($SplitParts.Count -ge 2) {
                    $PreDate = $SplitParts[0]  # Aquí está la Razón (Action)
                    $PostDate = $SplitParts[1] # Aquí está el Nombre del Archivo (+ basura numérica)

                    # --- A. ANALIZAR ACCIÓN (PRE-DATE) ---
                    $Action = "OTRO"
                    if ($PreDate -match "Elimina" -or $PreDate -match "Borrado" -or $PreDate -match "0x8") { $Action = "BORRADO (Deleted)" }
                    elseif ($PreDate -match "Creaci" -or $PreDate -match "Nacido" -or $PreDate -match "0x100") { $Action = "CREADO (Born)" }
                    elseif ($PreDate -match "Renombrado" -or $PreDate -match "0x2000") { $Action = "RENOMBRADO" }
                    elseif ($PreDate -match "Truncamiento" -or $PreDate -match "Datos escritos" -or $PreDate -match "0x0") { $Action = "MODIFICADO" }

                    # --- B. ANALIZAR NOMBRE (POST-DATE) ---
                    # PostDate será algo como: " | 120 " o " | 128 | mi_archivo.exe"
                    # Eliminamos comas, comillas y espacios de los bordes
                    $RawName = $PostDate.Trim().Trim(',').Trim('"')
                    
                    # DIVIDIMOS POR ESPACIOS O COMAS para encontrar texto real
                    # Los atributos suelen ser números solos (120, 128, 32). El nombre tiene letras.
                    $NameParts = $RawName -split "[, ]+"
                    $RealFileName = ""

                    # Recorremos las partes buscando la que NO sea un número simple
                    foreach ($part in $NameParts) {
                        $part = $part.Trim()
                        # Si tiene letras o puntos, es el archivo
                        if ($part -match "[a-zA-Z\.]" -and $part -notmatch "^\d+$") {
                            $RealFileName = $part
                        }
                        # Si ya tenemos un nombre y viene otro texto, concatenamos (nombres con espacios)
                        elseif ($RealFileName -ne "" -and $part -ne "") {
                             $RealFileName = "$RealFileName $part"
                        }
                    }

                    # --- GUARDAR RESULTADO ---
                    # Filtros de ruido
                    if ($RealFileName -ne "" -and $RealFileName -notmatch "^\$" -and $RealFileName -notmatch "\.tmp$") {
                         if ($Action -ne "OTRO") {
                            $JournalEvents += @{
                                Action = $Action
                                File   = $RealFileName
                                Date   = $FullDate
                            }
                        }
                    }
                }
            }
        }
        $Results += @{ Type="USN_JOURNAL"; Data=$JournalEvents }

    } catch {
        $Results += @{ Type="ERROR_USN"; Msg=$_.Exception.Message }
    }

    $Results | ConvertTo-Json -Depth 4 -Compress
    """

    with open(config.reporte_eventos, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DEFENDER & USN FORENSICS REPORT ===\n")
        f.write(f"Scan Time: {datetime.datetime.now()}\n\n")

        try:
            # Ejecutar PS
            proc = subprocess.Popen(['powershell', '-NoProfile', '-Command', ps_command], 
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    text=True, encoding='utf-8', errors='ignore', creationflags=0x08000000)
            out, err = proc.communicate()
            
            if not out.strip():
                f.write("[INFO] No data retrieved (Admin privileges required).\n")
                return

            try:
                data_list = json.loads(out)
                if isinstance(data_list, dict): data_list = [data_list]
            except:
                data_list = []
                f.write("[ERROR] JSON Parse Error.\n")

            active_output = []
            deleted_output = []
            usn_timeline = []

            for entry in data_list:
                mtype = entry.get("Type")
                data = entry.get("Data")
                if not data: continue

                if mtype == "ACTIVE":
                    paths = data.get("Paths") or []
                    if isinstance(paths, str): paths = [paths]
                    for p in paths: active_output.append(f"PATH: {p}")
                
                elif mtype == "DELETED_VSS":
                    if isinstance(data, dict): data = [data]
                    for x in data:
                        target = x.get("Target")
                        date = x.get("FoundIn")
                        deleted_output.append(f"Target: {target} (Backup: {date})")

                elif mtype == "USN_JOURNAL":
                    if isinstance(data, dict): data = [data]
                    for x in data:
                        action = x.get("Action")
                        fname = x.get("File")
                        date = x.get("Date")
                        
                        symbol = "[?]"
                        if "BORRADO" in action: symbol = "[X]"
                        elif "CREADO" in action: symbol = "[+]"
                        elif "MODIFICADO" in action: symbol = "[M]"
                        elif "RENOMBRADO" in action: symbol = "[R]"

                        usn_timeline.append(f"{symbol} {date} | {action} | {fname}")

            # --- ESCRITURA FINAL ---
            f.write("==================================================\n")
            f.write("[1] EXCLUSIONES ACTIVAS (PRESENT)\n")
            f.write("==================================================\n")
            if active_output:
                for x in active_output: f.write(f"[!!!] {x}\n")
            else: f.write("[OK] Clean.\n")
            f.write("\n")

            f.write("==================================================\n")
            f.write("[2] EXCLUSIONES ELIMINADAS (VSS BACKUP CHECK)\n")
            f.write("==================================================\n")
            if deleted_output:
                for x in deleted_output: f.write(f"[REMOVED] {x}\n{'-'*40}\n")
            else: f.write("[OK] Registry matches the last backup.\n")
            f.write("\n")

            f.write("==================================================\n")
            f.write("[3] ACTIVIDAD DE DISCO (UNIVERSAL PARSER)\n")
            f.write("    [Icono] Fecha Hora | Acción | Nombre del Archivo\n")
            f.write("==================================================\n")
            
            if usn_timeline:
                # Invertir para mostrar lo más reciente arriba
                for x in reversed(usn_timeline):
                    f.write(f"{x}\n")
            else:
                f.write("[INFO] No file activity retrieved.\n")

        except Exception as e:
            f.write(f"[CRITICAL ERROR] {e}\n")

    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_eventos)), {'f13': {'active': True}})
    except: pass



# --- F14: PROCESS HUNTER (OPTIMIZADA) ---
def fase_process_hunter(context, palabras, modo):
    """OPTIMIZADA: Usa context.process_snapshot"""
    if config.CANCELAR_ESCANEO: return
    print(f"[14/24] Process Genealogy Hunter (Parent-Child Analysis) [LETHAL]...")
    
    # Asegurar ruta
    if not config.reporte_process: config.reporte_process = "Process_Hunter.txt"
    
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong), ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong), ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_char * 260)]
    
    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    GENEALOGY_RULES = {"svchost.exe": ["services.exe"], "lsass.exe": ["wininit.exe"], "services.exe": ["wininit.exe"], "lsm.exe": ["wininit.exe"], "csrss.exe": ["smss.exe"], "wininit.exe": ["smss.exe"], "winlogon.exe": ["smss.exe"], "spoolsv.exe": ["services.exe"], "taskhostw.exe": ["svchost.exe", "explorer.exe", "services.exe"], "sihost.exe": ["svchost.exe"], "fontdrvhost.exe": ["wininit.exe", "winlogon.exe"], "dwm.exe": ["winlogon.exe"]}
    LEGIT_PATHS = {"svchost.exe": r"c:\windows\system32", "lsass.exe": r"c:\windows\system32", "csrss.exe": r"c:\windows\system32", "wininit.exe": r"c:\windows\system32", "services.exe": r"c:\windows\system32", "winlogon.exe": r"c:\windows\system32", "explorer.exe": r"c:\windows", "conhost.exe": r"c:\windows\system32"}

    with open(config.reporte_process, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== PROCESS GENEALOGY & MASQUERADE HUNTER: {datetime.datetime.now()} ===\n")
        f.write("Strategy: Native Snapshot + Parent/Child Validation + Path Check\n\n")
        
        # --- PARTE 1: SNAPSHOT EN TIEMPO REAL ---
        f.write("--- LIVE PROCESS ANALYSIS ---\n")
        h_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        if h_snap == -1:
            f.write("[ERROR] Could not take process snapshot.\n")
            return
            
        proc_map = {}
        if ctypes.windll.kernel32.Process32First(h_snap, ctypes.byref(pe32)):
            while True:
                pid = pe32.th32ProcessID
                ppid = pe32.th32ParentProcessID
                name = pe32.szExeFile.decode('cp1252', 'ignore').lower()
                proc_map[pid] = {"name": name, "ppid": ppid, "path": "Unknown"}
                if not ctypes.windll.kernel32.Process32Next(h_snap, ctypes.byref(pe32)): break
        ctypes.windll.kernel32.CloseHandle(h_snap)
        
        buffer = ctypes.create_unicode_buffer(1024)
        count_susp = 0
        
        for pid, info in proc_map.items():
            if config.CANCELAR_ESCANEO: break
            name = info["name"]
            ppid = info["ppid"]
            
            h_proc = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            real_path = ""
            if h_proc:
                size = ctypes.c_ulong(1024)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(h_proc, 0, buffer, ctypes.byref(size)):
                    real_path = buffer.value.lower()
                    info["path"] = real_path
                ctypes.windll.kernel32.CloseHandle(h_proc)
                
            is_suspicious = False
            reasons = []
            
            # Check 1: Ruta legítima
            if name in LEGIT_PATHS:
                expected_dir = LEGIT_PATHS[name]
                if real_path and not real_path.startswith(expected_dir):
                    is_suspicious = True
                    reasons.append(f"FAKE PATH: Running from {real_path} (Expected: {expected_dir})")
            
            # Check 2: Genealogía (Padre correcto)
            if name in GENEALOGY_RULES:
                parent_info = proc_map.get(ppid)
                if parent_info:
                    parent_name = parent_info["name"]
                    allowed_parents = GENEALOGY_RULES[name]
                    if parent_name not in allowed_parents:
                        is_suspicious = True
                        reasons.append(f"BAD PARENT: Spawmed by '{parent_name}' (PID {ppid}). Expected: {allowed_parents}")
            
            # Check 3: Rutas peligrosas (Temp/AppData)
            if real_path and ("\\temp\\" in real_path or "\\appdata\\" in real_path or "\\downloads\\" in real_path):
                if name.endswith(".exe"):
                    if any(k in name for k in ["loader", "client", "cheat", "inject"]):
                         is_suspicious = True
                         reasons.append("Running from TEMP/APPDATA with suspicious name")
                    elif modo == "Analizar Todo":
                         reasons.append("Running from TEMP/APPDATA")
                         
            # Check 4: Palabras clave
            if any(p in name for p in palabras) or any(p in real_path for p in palabras):
                is_suspicious = True
                reasons.append("Keyword Match")
                
            if is_suspicious:
                count_susp += 1
                f.write(f"[!!!] PROCESS ANOMALY: {name} (PID {pid})\n")
                f.write(f"      Path: {real_path}\n")
                f.write(f"      Parent PID: {ppid} ({proc_map.get(ppid, {}).get('name', 'Unknown')})\n")
                f.write(f"      Detection: {', '.join(reasons)}\n")
                f.write("-" * 50 + "\n")
                f.flush()
            elif modo == "Analizar Todo" and real_path:
                f.write(f"[LIVE] {name} (PID {pid}) -> {real_path}\n")
                
        if count_susp == 0: f.write("[OK] No process genealogy anomalies found.\n")
        
        # --- PARTE 2: PROCESOS MUERTOS ---
        f.write("\n--- DEAD PROCESSES (Last 45 mins) ---\n")
        try:
            ps = "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4689} -ErrorAction SilentlyContinue | Where-Object {$_.TimeCreated -ge (Get-Date).AddMinutes(-45)} | Select-Object @{N='Time';E={$_.TimeCreated.ToString('HH:mm:ss')}}, @{N='Name';E={$_.Properties[0].Value}} | Format-Table -HideTableHeaders"
            proc = subprocess.Popen(f'powershell -NoProfile -Command "{ps}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, encoding='cp850', errors='ignore', creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                unique_procs = set()
                for l in out.splitlines():
                    clean_l = l.strip()
                    if clean_l: unique_procs.add(clean_l)
                for p in unique_procs:
                     if modo == "Analizar Todo" or any(k in p.lower() for k in palabras): 
                         f.write(f"[DEAD] {p}\n"); f.flush()
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_process)), {'f14': {'active': True}})
    except: pass

# --- F15: GAME CHEAT HUNTER (OPTIMIZADA) ---
def fase_game_cheat_hunter(context, palabras, modo):
    """OPTIMIZADA: Usa context.file_snapshot"""
    if config.CANCELAR_ESCANEO: return
    print("[15/25] Game Cheat Hunter (SURGICAL PRECISION | ZERO FP)")
    
    # Asegurar ruta
    if not config.reporte_game: config.reporte_game = "Game_Cheat_Hunter.txt"
    
    yara_rules = config.GLOBAL_YARA_RULES
    yara_active = False
    try:
        import yara
        YARA_AVAILABLE = True
    except: YARA_AVAILABLE = False
    if yara_rules is not None: yara_active = True
    elif YARA_AVAILABLE:
        try:
            ruta_reglas = resource_path("reglas_scanneler.yar")
            yara_rules = yara.compile(filepath=ruta_reglas)
            yara_active = True
        except: yara_rules = None

    INTERNAL_BLACKLIST = ["cheat", "hack", "injector", "loader", "spoofer", "aimbot", "esp", "imgui", "hook", "dumper", "bypass", "wesh", "kero", "skinchanger", "readwritememory", "kernel"]
    target_exts = ('.exe', '.dll', '.sys', '.bin', '.dat')
    MAX_SIZE_MB = 150 
    READ_LIMIT_MB = 15
    
    detections = 0
    scanned_count = 0

    with open(config.reporte_game, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== GAME CHEAT HUNTER (MEMORY SNAPSHOT): {datetime.datetime.now()} ===\n")
        f.write(f"Strategy: Using Context Snapshot + YARA + Entropy\n\n")
        
        # Usar snapshot en memoria en lugar de os.walk lento
        for file_data in context.file_snapshot:
            if config.CANCELAR_ESCANEO: break
            
            path = file_data['path']
            name = file_data['name']
            ext = file_data['ext']
            size = file_data['size']
            
            if not ext in target_exts: continue
            if size > MAX_SIZE_MB * 1024 * 1024: continue
            
            scanned_count += 1
            suspicious = False
            reasons = []
            metadata_dirty = False
            is_signed = False
            
            # 1. Metadata Check
            try:
                pe = pefile.PE(path, fast_load=True)
                sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                if sec_dir.VirtualAddress != 0 and sec_dir.Size > 0: is_signed = True
                
                if hasattr(pe, 'FileInfo'):
                    for info in pe.FileInfo:
                        if hasattr(info, 'StringTable'):
                            for st in info.StringTable:
                                for k, v in st.entries.items():
                                    val = v.decode(errors="ignore").lower()
                                    for bad in INTERNAL_BLACKLIST:
                                        if bad in val:
                                            metadata_dirty = True
                                            reasons.append(f"Blacklisted Metadata: {val}")
                pe.close()
            except: pass
            
            should_scan = False
            if metadata_dirty: should_scan = True
            elif not is_signed: should_scan = True
            elif is_signed and ("temp" in path.lower() or "appdata" in path.lower()): should_scan = True
            
            if not should_scan: continue
            
            # 2. Deep Scan
            try:
                with open(path, "rb") as bf:
                    data_start = bf.read(READ_LIMIT_MB * 1024 * 1024)
                    
                    # Entropy Check
                    entropy_val = calculate_entropy(data_start)
                    threshold = 7.4 if is_signed else 7.25
                    if entropy_val > threshold:
                        suspicious = True
                        reasons.append(f"High Entropy ({entropy_val:.2f})")
                    
                    # YARA Check
                    if yara_active:
                        try:
                            matches = yara_rules.match(data=data_start)
                            if matches:
                                suspicious = True
                                rules = [m.rule for m in matches]
                                reasons.append(f"YARA MATCH: {rules}")
                        except: pass
                        
            except: continue
            
            if suspicious:
                detections += 1
                tag = "[!!!]"
                if "YARA" in str(reasons) or metadata_dirty: tag = "[☢] CONFIRMED"
                
                f.write(f"{tag} THREAT DETECTED: {name}\n")
                f.write(f"      Path: {path}\n")
                f.write(f"      Status: {'SIGNED' if is_signed else 'UNSIGNED'}\n")
                f.write(f"      Reasons: {', '.join(reasons)}\n")
                f.write("-" * 55 + "\n")
                
        f.write(f"\nScan finished. Scanned: {scanned_count} | Detections: {detections}\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_game)), {'f15': {'active': True}})
    except: pass


# --- F16: NUCLEAR TRACES ---
def fase_nuclear_traces(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[16/24] Nuclear Traces (Clean Layout)...")
    
    # Asegurar ruta
    config.reporte_nuclear = asegurar_ruta_reporte("Nuclear_Traces.txt")
    
    now = datetime.datetime.now()
    limit_time = now - datetime.timedelta(hours=24) 

    # ==============================================================================
    # 0. OBTENER PROCESOS ACTIVOS
    # ==============================================================================
    running_names = []
    try:
        import psutil
        for p in psutil.process_iter(['name']):
            try:
                running_names.append(p.info['name'].lower())
            except: pass
    except: pass

    # ==============================================================================
    # 1. RECOLECCIÓN BAM
    # ==============================================================================
    bam_entries = []
    
    try:
        bam_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path, 0, winreg.KEY_READ) as k_bam:
            num_sids = winreg.QueryInfoKey(k_bam)[0]
            for i in range(num_sids):
                sid = winreg.EnumKey(k_bam, i)
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{bam_path}\\{sid}", 0, winreg.KEY_READ) as k_user:
                        num_vals = winreg.QueryInfoKey(k_user)[1]
                        for j in range(num_vals):
                            exe_path, value_data, type_ = winreg.EnumValue(k_user, j)
                            
                            exec_time = None
                            try:
                                if type_ == winreg.REG_BINARY and len(value_data) >= 8:
                                    filetime_int = struct.unpack('<Q', value_data[:8])[0]
                                    exec_time = filetime_to_dt(filetime_int)
                            except: pass
                            
                            if not exec_time: continue 

                            if "\\Device\\HarddiskVolume" in exe_path: 
                                exe_path = exe_path.replace("\\Device\\HarddiskVolume", "Volume_")
                            
                            bam_entries.append({
                                'time': exec_time,
                                'path': exe_path,
                                'sid': sid
                            })
                except: pass
    except Exception as e:
        print(f"Error reading BAM: {e}")

    # Ordenar: Más reciente arriba
    bam_entries.sort(key=lambda x: x['time'], reverse=True)

    # ==============================================================================
    # 2. ESCRITURA DEL REPORTE
    # ==============================================================================
    with open(config.reporte_nuclear, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NUCLEAR TRACES: {now.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write("Scope: BAM Execution History + LIVE STATE CHECK\n")
        
        # --- SECCIÓN A: BAM ---
        f.write("\n" + "="*80 + "\n")
        f.write(" [A] BAM EXECUTION TIMELINE (LAST 24H)\n")
        f.write("="*80 + "\n")
        # Columnas limpias: FECHA | ESTADO | RUTA
        f.write(f"{'TIMESTAMP':<20} | {'STATE':<10} | PATH\n")
        f.write("-" * 100 + "\n")
        
        count_bam_hits = 0
        
        for entry in bam_entries:
            if entry['time'] < limit_time: continue 

            time_str = entry['time'].strftime('%Y-%m-%d %H:%M:%S')
            path_lower = entry['path'].lower()
            file_name = os.path.basename(path_lower)
            
            # --- DETERMINAR ESTADO (OPEN / CLOSED) ---
            state_str = "[CLOSED]"
            if file_name in running_names:
                state_str = "[OPEN]  " 
            
            # --- FILTRADO INTERNO (Para saber qué mostrar) ---
            hit = False
            
            if "temp" in path_lower or "appdata" in path_lower:
                if any(k in path_lower for k in ["cheat", "loader", "inject", "priv", "vip", "client"]): 
                    hit = True
                elif modo == "Analizar Todo" and ".exe" in path_lower:
                    pass # Se mostrará por la condición 'Analizar Todo' abajo
            
            if "volume_" in path_lower and "program files" not in path_lower and "windows" not in path_lower: 
                hit = True
            
            if any(p in path_lower for p in palabras): 
                hit = True

            # Escribir línea (SIN COLUMNA DE DETECCIÓN VISIBLE)
            if hit:
                f.write(f"{time_str:<20} | {state_str:<10} | {entry['path']}\n")
                count_bam_hits += 1
            elif modo == "Analizar Todo":
                if "windows\\" not in path_lower and "program files" not in path_lower:
                     f.write(f"{time_str:<20} | {state_str:<10} | {entry['path']}\n")

        if count_bam_hits == 0 and modo != "Analizar Todo":
            f.write("\n[OK] No suspicious execution traces found in BAM (Last 24h).\n")

        # --- SECCIÓN B: PIPES ---
        f.write("\n\n" + "="*80 + "\n")
        f.write(" [B] LIVE NAMED PIPES\n")
        f.write("="*80 + "\n")
        
        suspicious_pipes = ["cheat", "hack", "injector", "loader", "esp", "aim", "battleye", "easyanticheat", "faceit", "esea", "vanguard", "overlay", "hook", "auth"]
        
        try:
            pipes = os.listdir(r'\\.\pipe\\')
            found_pipe = False
            for pipe in pipes:
                pipe_lower = pipe.lower()
                if any(s in pipe_lower for s in suspicious_pipes): 
                    f.write(f"[!!!] THREAT PIPE DETECTED: {pipe}\n")
                    found_pipe = True
                elif len(pipe) > 20 and "-" in pipe and "{" not in pipe and "com" not in pipe:
                      if modo == "Analizar Todo": 
                          f.write(f"[INFO] SUSPICIOUS PATTERN: {pipe}\n")
                          found_pipe = True
            
            if not found_pipe: f.write("[OK] No suspicious named pipes found active.\n")
        except Exception as e: f.write(f"Error scanning pipes: {e}\n")

    try: generar_reporte_html(os.path.dirname(config.reporte_nuclear), {'f16': {'active': True}})
    except: pass
    
# --- F17: KERNEL HUNTER ---
def fase_kernel_hunter(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[17/24] Kernel Hunter (Drivers & Boot config) [NUCLEAR]...")
    
    # Asegurar ruta
    if not config.reporte_kernel: config.reporte_kernel = "Kernel_Anomalies.txt"
    
    vuln_drivers = ["iqvw64e.sys", "iqvw32e.sys", "capcom.sys", "gdrv.sys", "atszio.sys", "winio.sys", "ene.sys", "enetechio.sys", "msio64.sys", "glckio2.sys", "inpoutx64.sys", "rzpnk.sys"]
    
    with open(config.reporte_kernel, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== KERNEL HUNTER & ANOMALIES: {datetime.datetime.now()} ===\n\n")
        
        f.write("--- BOOT CONFIGURATION (Test Signing Check) ---\n")
        try:
            # Usar creationflags=0x08000000 para ocultar la ventana de consola
            proc = subprocess.Popen('bcdedit /enum {current}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            danger_flags = False
            if out:
                lines = out.splitlines()
                for l in lines:
                    low_l = l.lower()
                    if "testsigning" in low_l and "yes" in low_l: 
                        f.write("[!!!] CRITICAL: WINDOWS TEST SIGNING IS ON (Permite drivers de hacks no firmados)\n")
                        danger_flags = True
                    if "debug" in low_l and "yes" in low_l: 
                        f.write("[!!!] CRITICAL: KERNEL DEBUGGING IS ON (Usado para manipular memoria)\n")
                        danger_flags = True
                    if "nointegritychecks" in low_l and "yes" in low_l: 
                        f.write("[!!!] CRITICAL: INTEGRITY CHECKS DISABLED\n")
                        danger_flags = True
            if not danger_flags: f.write("[OK] Secure Boot Integrity appears normal.\n")
        except: f.write("Error reading BCD.\n")
        
        f.write("\n--- LOADED KERNEL DRIVERS SCAN ---\n")
        try:
            cmd = 'driverquery /v /fo csv'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if not l.strip(): continue
                    low_l = l.lower()
                    # Detectar drivers vulnerables
                    for vd in vuln_drivers:
                        if vd in low_l: 
                            f.write(f"[!!!] VULNERABLE DRIVER DETECTED: {l.strip()}\n      (Posible ataque KDMapper/Overlay Kernel)\n")
                            f.flush()
                    # Detectar drivers en rutas de usuario
                    if "users\\" in low_l or "appdata" in low_l or "temp" in low_l or "downloads" in low_l: 
                        clean_line = l.replace('"', '').strip()
                        f.write(f"[!!!] MALICIOUS DRIVER PATH: {clean_line}\n      (Driver cargando desde espacio de usuario)\n")
                        f.flush()
                    # Modo Analizar Todo
                    if modo == "Analizar Todo":
                        if "microsoft" not in low_l and "intel" not in low_l and "nvidia" not in low_l and "amd" not in low_l and "realtek" not in low_l: 
                            f.write(f"[UNKNOWN DRIVER] {l[:100]}...\n")
                            f.flush()
        except Exception as e: f.write(f"Error listing drivers: {e}\n")
        
        f.write("\n--- NETWORK TAMPERING (Hosts File) ---\n")
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as hf:
                    lines = hf.readlines()
                    found_tamper = False
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        bad_domains = ["vac", "battleye", "easyanticheat", "riot", "vanguard", "auth", "license"]
                        if any(b in line.lower() for b in bad_domains): 
                            f.write(f"[!!!] HOSTS TAMPERING: {line}\n")
                            found_tamper = True
                    if not found_tamper: f.write("[OK] Hosts file clean.\n")
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_kernel)), {'f17': {'active': True}})
    except: pass

# --- F18: DNA & PREFETCH ---
def fase_dna_prefetch(palabras, modo):
    """
    FASE 18: DNA & PREFETCH FORENSICS (Decompression + Deep Scan).
    Ordenado Cronológicamente (Newest -> Oldest).
    """
    if config.CANCELAR_ESCANEO: return
    print(f"[18/24] DNA & Prefetch Hunter (MAM Decompression) [FORENSIC]...")
    
    import ctypes
    import struct
    import datetime
    
    # Configuración de rutas
    try:
        base_path = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
        folder_name = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
    except:
        base_path = os.path.abspath(".")
        folder_name = "Resultados_SS"
        
    config.reporte_dna = os.path.join(base_path, folder_name, "DNA_Prefetch.txt")

    # --- CONFIGURACIÓN DE DESCOMPRESIÓN NATIVA (NTDLL) ---
    try:
        ntdll = ctypes.windll.ntdll
        RtlDecompressBuffer = ntdll.RtlDecompressBuffer
        COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004
    except:
        RtlDecompressBuffer = None

    def decompress_pf(filepath):
        try:
            with open(filepath, "rb") as f:
                header = f.read(8)
                f.seek(0)
                file_content = f.read()

            # Caso 1: Archivo Comprimido (Win 10/11) - Header "MAM"
            if header.startswith(b'MAM'):
                if not RtlDecompressBuffer: return None
                
                decompressed_size = struct.unpack('<I', header[4:8])[0]
                out_buffer = ctypes.create_string_buffer(decompressed_size)
                final_size = ctypes.c_ulong(0)
                compressed_data = file_content[8:]
                in_buffer = ctypes.create_string_buffer(compressed_data)
                
                status = RtlDecompressBuffer(
                    COMPRESSION_FORMAT_XPRESS_HUFF,
                    out_buffer, decompressed_size,
                    in_buffer, len(compressed_data),
                    ctypes.byref(final_size)
                )
                
                if status == 0: return out_buffer.raw
                else: return None

            # Caso 2: Archivo Sin Comprimir - Header "SCCA"
            elif header.startswith(b'SCCA'):
                return file_content
            
            return None
        except: return None

    # Listas de búsqueda
    suspicious_imports = [b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx", b"OpenProcess", 
                          b"LdrLoadDll", b"NtCreateThreadEx", b"SetWindowsHookExA", b"Wow64Transition"]
    
    user = os.environ.get("USERPROFILE", "C:\\")
    hot_paths = [
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "AppData", "Local", "Temp")
    ]
    
    deep_scan_targets = ["csgo", "discord", "explorer", "steam", "dota", "valorant", "javaw", "minecraft", "anydesk", "teamviewer"]

    # Preparamos el buffer de escritura
    with open(config.reporte_dna, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DNA & PREFETCH FORENSICS: {datetime.datetime.now()} ===\n")
        
        # ---------------------------------------------------------
        # PARTE 1: DNA (Imports) - Se mantiene igual
        # ---------------------------------------------------------
        f.write("--- [1] EXECUTABLE DNA (Static Import Analysis) ---\n")
        dna_hits = 0
        try:
            for target_dir in hot_paths:
                if not os.path.exists(target_dir): continue
                with os.scandir(target_dir) as entries:
                    for entry in entries:
                        if entry.is_file() and entry.name.lower().endswith('.exe'):
                            if entry.stat().st_size > 20 * 1024 * 1024: continue
                            try:
                                pe = pefile.PE(entry.path, fast_load=True)
                                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                                found_apis = []
                                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                                    for mod in pe.DIRECTORY_ENTRY_IMPORT:
                                        for imp in mod.imports:
                                            if imp and imp.name and imp.name in suspicious_imports:
                                                found_apis.append(imp.name.decode('utf-8'))
                                pe.close()
                                
                                if len(found_apis) >= 2:
                                    f.write(f"[!!!] INJECTOR DNA: {entry.name}\n")
                                    f.write(f"      Path: {entry.path}\n")
                                    f.write(f"      APIs: {', '.join(found_apis)}\n")
                                    f.write("-" * 40 + "\n")
                                    dna_hits += 1
                            except: pass
        except Exception as e: f.write(f"DNA Scan Error: {e}\n")
        if dna_hits == 0: f.write("[OK] No high-risk injectors found in hot folders.\n")

        # ---------------------------------------------------------
        # PARTE 2: PREFETCH (MODIFICADA PARA ORDEN CRONOLÓGICO)
        # ---------------------------------------------------------
        f.write("\n--- [2] PREFETCH TRACE CHAINS (Time Sorted) ---\n")
        pf_dir = r"C:\Windows\Prefetch"
        
        prefetch_entries = [] # Lista para almacenar antes de escribir

        if os.path.exists(pf_dir):
            try:
                # Usamos try/finally o context manager si tienes uno definido para FS Redirection
                # Asumo que existe DisableFileSystemRedirection o similar en tu código global
                # si no, simplemente quita el 'with Disable...'
                try:
                    fs_redirect = DisableFileSystemRedirection()
                    fs_redirect.__enter__()
                except: fs_redirect = None

                pf_files = [x for x in os.listdir(pf_dir) if x.lower().endswith(".pf")]
                
                for pf in pf_files:
                    if config.CANCELAR_ESCANEO: break
                    
                    full_pf_path = os.path.join(pf_dir, pf)
                    
                    # 1. Obtener TIMESTAMP (La clave del ordenamiento)
                    try:
                        mtime = os.path.getmtime(full_pf_path)
                        dt_object = datetime.datetime.fromtimestamp(mtime)
                    except:
                        continue # Si no podemos leer la fecha, saltamos

                    pf_lower = pf.lower()
                    is_suspicious_name = any(p in pf_lower for p in palabras)
                    should_deep_scan = is_suspicious_name or any(t in pf_lower for t in deep_scan_targets)
                    
                    evidence_found = []
                    
                    # Análisis profundo (Strings dentro del PF)
                    if should_deep_scan:
                        content = decompress_pf(full_pf_path)
                        if content:
                            try:
                                for kw in palabras:
                                    kw_bytes = kw.encode("utf-16-le")
                                    if kw_bytes in content:
                                        evidence_found.append(f"Loaded Module: {kw}")
                            except: pass
                    
                    # Guardamos en la lista SI es relevante
                    if is_suspicious_name or evidence_found or (modo == "Analizar Todo" and should_deep_scan):
                        prefetch_entries.append({
                            'timestamp': mtime,     # Para ordenar (float)
                            'dt_obj': dt_object,    # Para mostrar (datetime)
                            'filename': pf,
                            'suspicious': is_suspicious_name,
                            'evidence': evidence_found
                        })

                if fs_redirect: fs_redirect.__exit__(None, None, None)

            except Exception as e: f.write(f"[ERROR] Prefetch Access: {e}\n")
            
            # ---------------------------------------------------------
            # ORDENAMIENTO Y ESCRITURA
            # ---------------------------------------------------------
            # Ordenamos la lista: reverse=True pone los más recientes primero
            prefetch_entries.sort(key=lambda x: x['timestamp'], reverse=True)
            
            if not prefetch_entries:
                f.write("[OK] No suspicious prefetch traces found.\n")
            else:
                for entry in prefetch_entries:
                    time_str = entry['dt_obj'].strftime("%Y-%m-%d %H:%M:%S")
                    tag = "[SUSPICIOUS]" if entry['suspicious'] else "[INFO]"
                    
                    f.write(f"{tag} {time_str} | {entry['filename']}\n")
                    
                    if entry['suspicious']:
                        f.write(f"      Detection: Suspicious Filename Keyword\n")
                    
                    if entry['evidence']:
                        f.write(f"      INTERNAL TRACES (Decompressed Analysis):\n")
                        for ev in entry['evidence']:
                            f.write(f"      > {ev}\n")
                    
                    f.write("-" * 80 + "\n")

        else: f.write("[ERROR] Prefetch folder not found (Admin required).\n")
    
    # INTEGRACIÓN HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_dna)), {'f18': {'active': True}})
    except: pass

# --- F19: NETWORK HUNTER ---
def fase_network_hunter(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[19/24] Network Hunter (Connections & History) [LIVE+FORENSIC]...")
    
    # Asegurar ruta
    if not config.reporte_network: config.reporte_network = "Network_Anomalies.txt"

    with open(config.reporte_network, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NETWORK & DOWNLOAD FORENSICS: {datetime.datetime.now()} ===\n\n")
        safe_ports = ["80", "443", "53", "135", "139", "445"]
        f.write("--- LIVE CONNECTIONS (Netstat) ---\n")
        try:
            proc = subprocess.Popen('netstat -ano', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if "TCP" not in l and "UDP" not in l: continue
                    parts = l.split()
                    if len(parts) < 4: continue
                    proto = parts[0]
                    remote = parts[2]
                    state = parts[3] if "TCP" in proto else "UDP"
                    pid = parts[-1] if "TCP" in proto else parts[-1]
                    
                    if "127.0.0.1" in remote or "[::]" in remote or "*:*" in remote or "0.0.0.0" in remote: continue
                    
                    port = remote.split(":")[-1]
                    is_suspicious = False
                    reason = ""
                    if port not in safe_ports and state == "ESTABLISHED": 
                        is_suspicious = True
                        reason = f"Non-Standard Port {port}"
                    
                    if is_suspicious or modo == "Analizar Todo":
                        marker = "[!!!] " if is_suspicious else "      "
                        f.write(f"{marker}{proto} {remote} {state} PID:{pid} {reason}\n")
                        f.flush()
        except: f.write("Error running netstat.\n")
        
        f.write("\n--- POWERSHELL DOWNLOAD HISTORY ---\n")
        history_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8", errors="ignore") as h:
                    lines = h.readlines()
                    for line in lines:
                        line = line.strip()
                        line_low = line.lower()
                        if any(x in line_low for x in ["http://", "https://", "wget", "curl", "bits"]):
                            if not any(x in line_low for x in ["apache", "firewall", "policy", "allow"]):
                                f.write(f"[HISTORY TRACE] {line}\n")
                                f.flush()
            except: f.write("Error reading PowerShell history.\n")
        else: f.write("No PowerShell history found.\n")
        
        f.write("\n--- BITS TRANSFER HISTORY (Hidden Downloads) ---\n")
        try:
            cmd_bits = "Get-BitsTransfer -AllUsers | Select-Object -Property JobId, CreationTime, State, FileList | Format-List"
            proc_b = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd_bits], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out_b, _ = proc_b.communicate()
            if out_b.strip(): 
                f.write(out_b)
                f.flush()
            else: f.write("No active background transfers found.\n")
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_network)), {'f19': {'active': True}})
    except: pass


# --- F20: TOXIC LNK ---
def fase_toxic_lnk(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[20/24] Toxic & LNK Hunter (Anti-Bypass) [FORENSIC]...")
    
    # Asegurar ruta
    if not config.reporte_toxic: config.reporte_toxic = "Toxic_LNK.txt"

    with open(config.reporte_toxic, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== TOXIC LNK & MODULE SCAN: {datetime.datetime.now()} ===\n")
        f.write("Searching for: LNKs pointing to deleted files (Evidence Tampering) & Toxic Modules in RAM\n\n")
        
        f.write("--- ORPHANED SHORTCUTS (LNK) ---\n")
        recent_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Recent")
        if os.path.exists(recent_path):
            try:
                ps_script = f"""
                Get-ChildItem -Path '{recent_path}' -Filter *.lnk | ForEach-Object {{
                    try {{
                        $sh = New-Object -ComObject WScript.Shell
                        $lnk = $sh.CreateShortcut($_.FullName)
                        $target = $lnk.TargetPath
                        if ($target -and (Test-Path $target) -eq $false) {{
                            Write-Output "BROKEN|$($_.Name)|$target"
                        }} elseif ($target -match 'Temp|Downloads') {{
                             Write-Output "RISKY|$($_.Name)|$target"
                        }}
                    }} catch {{}}
                }}
                """
                proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
                out, _ = proc.communicate()
                if out:
                    for line in out.splitlines():
                        if "|" in line:
                            parts = line.split("|")
                            if len(parts) >= 3:
                                type_lnk = parts[0]
                                name = parts[1]
                                target = parts[2]
                                is_suspicious = False
                                
                                if type_lnk == "BROKEN":
                                    if target.lower().endswith((".exe", ".bat")): is_suspicious = True
                                if any(p in target.lower() for p in palabras): is_suspicious = True
                                
                                if is_suspicious or modo == "Analizar Todo":
                                    marker = "[!!!]" if is_suspicious else "[INFO]"
                                    desc = "DELETED FILE EVIDENCE" if type_lnk == "BROKEN" else "Risky Location"
                                    f.write(f"{marker} {name} -> {target} ({desc})\n")
                                    f.flush()
            except Exception as e: f.write(f"Error scanning LNKs: {e}\n")
            
        f.write("\n--- TOXIC MODULES IN RAM ---\n")
        try:
            cmd = 'tasklist /m /fo csv'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for line in lines:
                    if "Image Name" in line: continue
                    if any(k in line.lower() for k in ["cheat", "inject", "hook", "hack"]):
                        f.write(f"[!!!] TOXIC MODULE: {line[:100]}...\n")
                        f.flush()
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_toxic)), {'f20': {'active': True}})
    except: pass

# --- F19: NETWORK HUNTER ---
def fase_network_hunter(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[19/24] Network Hunter (Connections & History) [LIVE+FORENSIC]...")
    
    # Asegurar ruta
    if not config.reporte_network: config.reporte_network = "Network_Anomalies.txt"

    with open(config.reporte_network, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== NETWORK & DOWNLOAD FORENSICS: {datetime.datetime.now()} ===\n\n")
        safe_ports = ["80", "443", "53", "135", "139", "445"]
        f.write("--- LIVE CONNECTIONS (Netstat) ---\n")
        try:
            proc = subprocess.Popen('netstat -ano', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for l in lines:
                    if "TCP" not in l and "UDP" not in l: continue
                    parts = l.split()
                    if len(parts) < 4: continue
                    proto = parts[0]
                    remote = parts[2]
                    state = parts[3] if "TCP" in proto else "UDP"
                    pid = parts[-1] if "TCP" in proto else parts[-1]
                    
                    if "127.0.0.1" in remote or "[::]" in remote or "*:*" in remote or "0.0.0.0" in remote: continue
                    
                    port = remote.split(":")[-1]
                    is_suspicious = False
                    reason = ""
                    if port not in safe_ports and state == "ESTABLISHED": 
                        is_suspicious = True
                        reason = f"Non-Standard Port {port}"
                    
                    if is_suspicious or modo == "Analizar Todo":
                        marker = "[!!!] " if is_suspicious else "      "
                        f.write(f"{marker}{proto} {remote} {state} PID:{pid} {reason}\n")
                        f.flush()
        except: f.write("Error running netstat.\n")
        
        f.write("\n--- POWERSHELL DOWNLOAD HISTORY ---\n")
        history_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8", errors="ignore") as h:
                    lines = h.readlines()
                    for line in lines:
                        line = line.strip()
                        line_low = line.lower()
                        if any(x in line_low for x in ["http://", "https://", "wget", "curl", "bits"]):
                            if not any(x in line_low for x in ["apache", "firewall", "policy", "allow"]):
                                f.write(f"[HISTORY TRACE] {line}\n")
                                f.flush()
            except: f.write("Error reading PowerShell history.\n")
        else: f.write("No PowerShell history found.\n")
        
        f.write("\n--- BITS TRANSFER HISTORY (Hidden Downloads) ---\n")
        try:
            cmd_bits = "Get-BitsTransfer -AllUsers | Select-Object -Property JobId, CreationTime, State, FileList | Format-List"
            proc_b = subprocess.Popen(["powershell", "-NoProfile", "-Command", cmd_bits], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out_b, _ = proc_b.communicate()
            if out_b.strip(): 
                f.write(out_b)
                f.flush()
            else: f.write("No active background transfers found.\n")
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_network)), {'f19': {'active': True}})
    except: pass


# --- F20: TOXIC LNK ---
def fase_toxic_lnk(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[20/24] Toxic & LNK Hunter (Anti-Bypass) [FORENSIC]...")
    
    # Asegurar ruta
    if not config.reporte_toxic: config.reporte_toxic = "Toxic_LNK.txt"

    with open(config.reporte_toxic, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== TOXIC LNK & MODULE SCAN: {datetime.datetime.now()} ===\n")
        f.write("Searching for: LNKs pointing to deleted files (Evidence Tampering) & Toxic Modules in RAM\n\n")
        
        f.write("--- ORPHANED SHORTCUTS (LNK) ---\n")
        recent_path = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Recent")
        if os.path.exists(recent_path):
            try:
                ps_script = f"""
                Get-ChildItem -Path '{recent_path}' -Filter *.lnk | ForEach-Object {{
                    try {{
                        $sh = New-Object -ComObject WScript.Shell
                        $lnk = $sh.CreateShortcut($_.FullName)
                        $target = $lnk.TargetPath
                        if ($target -and (Test-Path $target) -eq $false) {{
                            Write-Output "BROKEN|$($_.Name)|$target"
                        }} elseif ($target -match 'Temp|Downloads') {{
                             Write-Output "RISKY|$($_.Name)|$target"
                        }}
                    }} catch {{}}
                }}
                """
                proc = subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
                out, _ = proc.communicate()
                if out:
                    for line in out.splitlines():
                        if "|" in line:
                            parts = line.split("|")
                            if len(parts) >= 3:
                                type_lnk = parts[0]
                                name = parts[1]
                                target = parts[2]
                                is_suspicious = False
                                
                                if type_lnk == "BROKEN":
                                    if target.lower().endswith((".exe", ".bat")): is_suspicious = True
                                if any(p in target.lower() for p in palabras): is_suspicious = True
                                
                                if is_suspicious or modo == "Analizar Todo":
                                    marker = "[!!!]" if is_suspicious else "[INFO]"
                                    desc = "DELETED FILE EVIDENCE" if type_lnk == "BROKEN" else "Risky Location"
                                    f.write(f"{marker} {name} -> {target} ({desc})\n")
                                    f.flush()
            except Exception as e: f.write(f"Error scanning LNKs: {e}\n")
            
        f.write("\n--- TOXIC MODULES IN RAM ---\n")
        try:
            cmd = 'tasklist /m /fo csv'
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
            if out:
                lines = out.splitlines()
                for line in lines:
                    if "Image Name" in line: continue
                    if any(k in line.lower() for k in ["cheat", "inject", "hook", "hack"]):
                        f.write(f"[!!!] TOXIC MODULE: {line[:100]}...\n")
                        f.flush()
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_toxic)), {'f20': {'active': True}})
    except: pass

# --- F21: GHOST TRAILS ---
def fase_ghost_trails(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[21/24] Ghost Trails (Registry MRU & ShellBags) [ANTI-CLEANER]...")
    
    # Asegurar ruta
    if not config.reporte_ghost: config.reporte_ghost = "Ghost_Trails.txt"

    with open(config.reporte_ghost, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== GHOST TRAILS & REGISTRY MRU: {datetime.datetime.now()} ===\n")
        f.write("Searching for: Evidence of files accessed via Dialogs, even if deleted.\n\n")
        
        f.write("--- OPENSAVEPIDLMRU (File Dialog History) ---\n")
        mru_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mru_path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    ext = winreg.EnumKey(key, i) 
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{mru_path}\\{ext}") as subkey:
                            count = winreg.QueryInfoKey(subkey)[1]
                            for j in range(count):
                                name, val, type = winreg.EnumValue(subkey, j)
                                if type == winreg.REG_BINARY:
                                    try:
                                        txt = val.decode('utf-16-le', errors='ignore')
                                        clean_txt = "".join([c for c in txt if c.isprintable() or c in ['\\', ':', '.', '_', '-']])
                                        paths = re.findall(r'[a-zA-Z]:\\[a-zA-Z0-9_\\\-\.\s]+', clean_txt)
                                        for p in paths:
                                            if len(p) > 5:
                                                is_susp = any(w in p.lower() for w in palabras)
                                                if is_susp or modo == "Analizar Todo": 
                                                    marker = "!!!" if is_susp else "INFO"
                                                    f.write(f"[{marker}] OPENED: {p}\n")
                                                    f.flush()
                                    except: pass
                    except: pass
        except: f.write("Could not access OpenSavePidlMRU.\n")
        
        f.write("\n--- MUICACHE (Application Names) ---\n")
        mui_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, val, _ = winreg.EnumValue(key, i)
                    if ".exe" in name.lower():
                         is_susp = any(w in name.lower() for w in palabras)
                         if is_susp or modo == "Analizar Todo": 
                             marker = "!!!" if is_susp else "INFO"
                             f.write(f"[{marker}] RAN: {name}\n")
                             f.flush()
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_ghost)), {'f21': {'active': True}})
    except: pass


# --- F22: MEMORY ANOMALY ---
def fase_memory_anomaly(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[22/24] Memory Anomaly Hunter (VAD + Orphan Threads) [GOD-TIER]...")
    
    # Asegurar ruta
    if not config.reporte_memory: config.reporte_memory = "Memory_Injection_Report.txt"
    
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong), ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong), ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong), ("th32ThreadID", ctypes.c_ulong), ("th32OwnerProcessID", ctypes.c_ulong), ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long), ("dwFlags", ctypes.c_ulong)]
    
    TH32CS_SNAPMODULE = 0x00000008; TH32CS_SNAPMODULE32 = 0x00000010; TH32CS_SNAPTHREAD = 0x00000004; THREAD_QUERY_INFORMATION = 0x0040; STATUS_SUCCESS = 0
    ntdll = ctypes.windll.ntdll; kernel32 = ctypes.windll.kernel32

    def get_valid_ranges(pid):
        valid_ranges = [] 
        h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if h_snap == -1: return []
        me32 = MODULEENTRY32()
        me32.dwSize = ctypes.sizeof(MODULEENTRY32)
        if kernel32.Module32First(h_snap, ctypes.byref(me32)):
            while True:
                start = me32.modBaseAddr if me32.modBaseAddr else 0
                size = me32.modBaseSize
                if start and size:
                    end = start + size
                    name = me32.szModule.decode('cp1252', 'ignore')
                    valid_ranges.append((start, end, name))
                if not kernel32.Module32Next(h_snap, ctypes.byref(me32)): break
        kernel32.CloseHandle(h_snap)
        return valid_ranges

    target_names = ["csgo.exe", "valorant.exe", "dota2.exe", "fortnite.exe", "javaw.exe", "explorer.exe", "svchost.exe", "discord.exe", "steam.exe", "hl2.exe", "gta5.exe", "fivem.exe", "robloxplayerbeta.exe", "minecraft.exe"]
    
    with open(config.reporte_memory, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== MEMORY FORENSICS (VAD & THREADS): {datetime.datetime.now()} ===\n")
        f.write("Scanning for: Unbacked Executable Memory & Orphan Threads (Injection Indicators)\n\n")
        
        cmd = 'tasklist /fo csv /nh'
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=0x08000000)
            out, _ = proc.communicate()
        except: return
        
        if not out: return
        
        for line in out.splitlines():
            if config.CANCELAR_ESCANEO: break
            parts = line.split(',')
            if len(parts) < 2: continue
            proc_name = parts[0].strip('"')
            try: pid = int(parts[1].strip('"'))
            except: continue
            
            check_process = False
            if modo == "Analizar Todo": check_process = True
            elif any(t in proc_name.lower() for t in target_names): check_process = True
            elif any(p in proc_name.lower() for p in palabras): check_process = True
            
            if not check_process: continue
            
            h_process = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
            if not h_process: continue
            
            f.write(f"--> Scanning PID {pid}: {proc_name}...\n"); f.flush()
            valid_modules = get_valid_ranges(pid)
            
            # 1. Orphan Threads
            if valid_modules:
                h_snap_thread = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)
                orphans_found = 0
                if kernel32.Thread32First(h_snap_thread, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == pid:
                            h_thread = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, te32.th32ThreadID)
                            if h_thread:
                                start_addr = ctypes.c_void_p()
                                status = ntdll.NtQueryInformationThread(h_thread, 9, ctypes.byref(start_addr), ctypes.sizeof(start_addr), None)
                                if status == STATUS_SUCCESS and start_addr.value:
                                    addr_val = start_addr.value
                                    is_valid = False
                                    for v_start, v_end, v_name in valid_modules:
                                        if v_start <= addr_val < v_end:
                                            is_valid = True
                                            break
                                    if not is_valid:
                                        orphans_found += 1
                                        f.write(f"   [!!!] ORPHAN THREAD DETECTED (TID: {te32.th32ThreadID})\n")
                                        f.write(f"         Start Address: 0x{addr_val:X}\n")
                                        f.write(f"         Analysis: Thread starts OUTSIDE any valid module.\n")
                                        f.write(f"         (High Probability of Manual Map / Code Injection)\n")
                                        f.write("-" * 40 + "\n"); f.flush()
                                kernel32.CloseHandle(h_thread)
                        if not kernel32.Thread32Next(h_snap_thread, ctypes.byref(te32)): break
                kernel32.CloseHandle(h_snap_thread)
                if orphans_found == 0: f.write("      [Threads OK] All threads act within valid modules.\n")
            
            # 2. VAD Anomalies
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            anomalies = 0
            while kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if config.CANCELAR_ESCANEO: break
                is_executable = (mbi.Protect & (0x10 | 0x20 | 0x40 | 0x80))
                if mbi.State == 0x1000 and mbi.Type == 0x20000 and is_executable:
                    size_kb = mbi.RegionSize / 1024
                    if size_kb > 8: 
                        anomalies += 1
                        prot_str = "UNKNOWN"
                        if mbi.Protect & 0x40: prot_str = "RWX (Read/Write/Exec)"
                        elif mbi.Protect & 0x20: prot_str = "RX (Read/Exec)"
                        f.write(f"   [!!!] VAD ANOMALY at 0x{address:X}\n")
                        f.write(f"         Size: {size_kb:.2f} KB\n")
                        f.write(f"         Protection: {prot_str}\n")
                        f.write(f"         Type: MEM_PRIVATE (No file on disk)\n")
                        f.write(f"         (Potential Unpacked Cheat Payload)\n")
                        f.write("-" * 40 + "\n"); f.flush()
                address += mbi.RegionSize
            kernel32.CloseHandle(h_process)
            f.write("\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_memory)), {'f22': {'active': True}})
    except: pass

# --- F23: ROGUE DRIVERS ---
def fase_rogue_drivers(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[23/24] Rogue Driver Hunter (Unlinked Modules) [GOD-TIER]...")
    
    # Asegurar ruta
    if not config.reporte_drivers: config.reporte_drivers = "Rogue_Drivers.txt"

    try:
        with open(config.reporte_drivers, "w", encoding="utf-8", buffering=1) as f:
            f.write(f"=== ROGUE KERNEL DRIVER SCAN: {datetime.datetime.now()} ===\n")
            f.write("Comparing: EnumDeviceDrivers (Memory) vs DriverQuery (Registry)\n")
            f.write("Looking for: Drivers loaded in memory but hidden from the system list.\n\n")
            f.flush()
            
            proc = subprocess.Popen('driverquery /nh', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, _ = proc.communicate()
            official_drivers = set()
            if out:
                for line in out.decode('cp850', errors='ignore').splitlines():
                    if line.strip(): official_drivers.add(line.split()[0].lower())
            
            psapi = ctypes.windll.psapi
            image_bases = (ctypes.c_void_p * 1024)()
            cb_needed = ctypes.c_long()
            
            if psapi.EnumDeviceDrivers(ctypes.byref(image_bases), ctypes.sizeof(image_bases), ctypes.byref(cb_needed)):
                drivers_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
                f.write(f"Drivers in Memory: {drivers_count} | Registered Drivers: {len(official_drivers)}\n\n")
                f.flush()
                
                for i in range(drivers_count):
                    base_addr = image_bases[i]
                    if not base_addr: continue
                    name_buffer = ctypes.create_unicode_buffer(256)
                    res = psapi.GetDeviceDriverBaseNameW(ctypes.c_void_p(base_addr), name_buffer, 256)
                    
                    if res > 0:
                        drv_name = name_buffer.value.lower()
                        if not drv_name.endswith(".sys"): 
                            f.write(f"[SUSPICIOUS] Non-SYS Driver: {drv_name} at {base_addr}\n"); f.flush()
                        if "iqvw" in drv_name or "capcom" in drv_name or "mhyprot" in drv_name: 
                            f.write(f"[!!!] VULNERABLE DRIVER (BYPASS TOOL): {drv_name}\n"); f.flush()
                    else: 
                        f.write(f"[!!!] UNNAMED DRIVER ANOMALY at address: {base_addr}\n      (Posible Kernel Manual Map / KDMapper artifact)\n"); f.flush()
            else: 
                f.write("Failed to enumerate device drivers (Need Admin?).\n"); f.flush()
    except Exception as e:
        try:
            with open("Driver_Error_Log.txt", "w") as err_f: err_f.write(f"Error scanning drivers: {e}")
        except: pass

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_drivers)), {'f23': {'active': True}})
    except: pass


# --- F24: DEEP STATIC ---
def fase_deep_static(*args):
    try:
        palabras = args[0]
        modo = "Normal"
        if len(args) > 1 and isinstance(args[-1], str): modo = args[-1]
    except: return
    
    # Asegurar ruta
    if not config.reporte_static: 
        try:
            base_path = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
            folder_name = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
            out_dir = os.path.join(base_path, folder_name)
            os.makedirs(out_dir, exist_ok=True)
            config.reporte_static = os.path.join(out_dir, "Deep_Static_Analysis.txt")
        except: config.reporte_static = "Deep_Static_Analysis.txt"

    try:
        import yara
        YARA_AVAILABLE = True
    except: YARA_AVAILABLE = False
    
    if config.CANCELAR_ESCANEO: return
    print("[24/25] Deep Static Heuristics (YARA FIXED | ENTROPY | FAST)")
    
    yara_rules = config.GLOBAL_YARA_RULES 
    yara_active = False
    if yara_rules is not None: yara_active = True
    elif YARA_AVAILABLE:
        try:
            ruta_reglas = resource_path("reglas_scanneler.yar")
            yara_rules = yara.compile(filepath=ruta_reglas)
            yara_active = True
        except Exception as e:
            yara_active = False
            print("[!] YARA load error:", e)

    user = os.environ.get("USERPROFILE", "C:\\")
    hunt_zones = [
        os.path.join(user, "Desktop"), 
        os.path.join(user, "Downloads"), 
        os.path.join(user, "AppData", "Local"), 
        os.path.join(user, "AppData", "Roaming")
    ]
    MAX_FILE_MB = 30; MAX_TIME = 10; start_time = time.time(); scanned = 0

    with open(config.reporte_static, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== DEEP STATIC ANALYSIS ===\n")
        f.write(f"Time: {datetime.datetime.now()}\n")
        if yara_active: f.write("YARA: ACTIVE (Rules Loaded)\n\n")
        elif not YARA_AVAILABLE: f.write("YARA: NOT INSTALLED (Module Missing)\n\n")
        else: f.write("YARA: FAILED (Rules file not found or compile error)\n\n")
        
        for zone in hunt_zones:
            if not os.path.exists(zone): continue
            for root, _, files in os.walk(zone):
                if config.CANCELAR_ESCANEO or time.time() - start_time > MAX_TIME: break
                
                rl = root.lower()
                if any(x in rl for x in ["windows", "microsoft", "google", "common files"]): continue
                
                for file in files:
                    if not file.lower().endswith((".exe", ".dll", ".sys")): continue
                    path = os.path.join(root, file)
                    try:
                        if os.path.getsize(path) > MAX_FILE_MB * 1024 * 1024: continue
                    except: continue
                    
                    try:
                        with open(path, "rb") as fd:
                            data = fd.read(2 * 1024 * 1024)
                            if not data: continue
                        scanned += 1
                        score = 0
                        reasons = []
                        
                        ent = calculate_entropy(data)
                        if ent > 7.2: score += 2; reasons.append(f"High entropy ({ent:.2f})")
                        
                        if yara_active:
                            try:
                                matches = yara_rules.match(data=data)
                                for m in matches:
                                    rn = m.rule
                                    if rn == "Inyeccion_y_Memoria": score += 5; reasons.append("YARA: Injection APIs")
                                    elif rn == "Cheat_Strings_Genericos": score += 4; reasons.append("YARA: Cheat strings")
                                    elif rn == "Sus_Config_Files": score += 3; reasons.append("YARA: Cheat config")
                                    else: score += 2; reasons.append(f"YARA: {rn}")
                            except: pass
                            
                        name = file.rsplit(".", 1)[0]
                        if len(name) <= 3 or name.isdigit(): score += 2; reasons.append("Suspicious filename")
                        
                        if score >= 4:
                            f.write(f"[!] STATIC THREAT: {file}\n    Path: {path}\n    Score: {score}\n    Reasons: {', '.join(reasons)}\n" + "-" * 50 + "\n")
                            f.flush()
                    except: pass
        f.write(f"\nScan completed. Files scanned: {scanned}\n")
    print("[✓] Deep Static completed")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_static)), {'f24': {'active': True}})
    except: pass

# --- F25: METAMORPHOSIS HUNTER ---
def fase_metamorphosis_hunter(context, palabras, modo, target_file=None):
    if config.CANCELAR_ESCANEO: return
    print("[25/25] Metamorphosis, Ghost Exe/DLL & Injection [NUCLEAR]")
    
    # Asegurar ruta
    if not config.reporte_morph: 
        try:
            base_path = config.HISTORIAL_RUTAS.get('path', os.path.abspath("."))
            folder_name = config.HISTORIAL_RUTAS.get('folder', "Resultados_SS")
            config.reporte_morph = os.path.join(base_path, folder_name, "Metamorphosis_DLL_Report.txt")
        except: config.reporte_morph = "Metamorphosis_DLL_Report.txt"
    
    # 1. Chequeo de Metamorfosis (Clones por Hash)
    hits = []
    if target_file and os.path.exists(target_file):
        try:
            target_size = os.path.getsize(target_file)
            with open(target_file, "rb") as f: target_hash = hashlib.sha256(f.read()).hexdigest()
            for f in context.file_snapshot:
                if f['size'] == target_size:
                    try:
                        with open(f['path'], "rb") as fo:
                            curr_hash = hashlib.sha256(fo.read()).hexdigest()
                        if curr_hash == target_hash: hits.append(f"Metamorphosis Clone: {f['path']}")
                    except: pass
        except: pass

    # 2. Chequeo de DLLs Tóxicas y Eventos USN
    yara_rules = config.GLOBAL_YARA_RULES
    if yara_rules is None:
        try:
            import yara
            path_rules = resource_path("reglas_scanneler.yar")
            yara_rules = yara.compile(filepath=path_rules)
        except: yara_rules = None
        
    start_time = time.time(); MAX_TIME = 300
    USN_REASON_DATA_EXTEND = 0x00000004; USN_REASON_DATA_TRUNCATION = 0x00000020; USN_REASON_FILE_CREATE = 0x00000100; USN_REASON_FILE_DELETE = 0x00000200; USN_REASON_CLOSE = 0x80000000 
    GENERIC_READ = 0x80000000; GENERIC_WRITE = 0x40000000; FILE_SHARE_READ = 0x00000001; FILE_SHARE_WRITE = 0x00000002; OPEN_EXISTING = 3; FSCTL_QUERY_USN_JOURNAL = 0x000900f4; FSCTL_READ_USN_JOURNAL = 0x000900bb
    class USN_JOURNAL_DATA_V0(ctypes.Structure): _fields_ = [("UsnJournalID", ctypes.c_ulonglong), ("FirstUsn", ctypes.c_ulonglong), ("NextUsn", ctypes.c_ulonglong), ("LowestValidUsn", ctypes.c_ulonglong), ("MaxUsn", ctypes.c_ulonglong), ("MaximumSize", ctypes.c_ulonglong), ("AllocationDelta", ctypes.c_ulonglong)]
    class READ_USN_JOURNAL_DATA_V0(ctypes.Structure): _fields_ = [("StartUsn", ctypes.c_ulonglong), ("ReasonMask", ctypes.c_uint), ("ReturnOnlyOnClose", ctypes.c_uint), ("Timeout", ctypes.c_ulonglong), ("BytesToWaitFor", ctypes.c_ulonglong), ("UsnJournalID", ctypes.c_ulonglong)]
    
    def name_entropy(name):
        if not name: return 0
        c = Counter(name); l = len(name); return -sum((n/l) * math.log(n/l, 2) for n in c.values())

    def get_usn_events_last_hour():
        events = []
        vol_handle = ctypes.windll.kernel32.CreateFileW(r"\\.\C:", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        if vol_handle == -1: return []
        try:
            journal_data = USN_JOURNAL_DATA_V0(); bytes_ret = ctypes.c_ulong()
            ctypes.windll.kernel32.DeviceIoControl(vol_handle, FSCTL_QUERY_USN_JOURNAL, None, 0, ctypes.byref(journal_data), ctypes.sizeof(journal_data), ctypes.byref(bytes_ret), None)
            read_data = READ_USN_JOURNAL_DATA_V0()
            read_data.StartUsn = max(0, journal_data.NextUsn - (120 * 1024 * 1024))
            read_data.ReasonMask = 0xFFFFFFFF; read_data.ReturnOnlyOnClose = 0; read_data.UsnJournalID = journal_data.UsnJournalID
            buf = ctypes.create_string_buffer(65536); limit_time = datetime.datetime.now() - datetime.timedelta(hours=1)
            while True:
                if config.CANCELAR_ESCANEO: break
                if not ctypes.windll.kernel32.DeviceIoControl(vol_handle, FSCTL_READ_USN_JOURNAL, ctypes.byref(read_data), ctypes.sizeof(read_data), buf, 65536, ctypes.byref(bytes_ret), None): break
                if bytes_ret.value < 8: break
                read_data.StartUsn = struct.unpack_from('<Q', buf, 0)[0]
                offset = 8
                while offset < bytes_ret.value:
                    if offset + 60 > bytes_ret.value: break
                    reclen = struct.unpack_from('<I', buf, offset)[0]
                    if reclen == 0: break
                    reason = struct.unpack_from('<I', buf, offset + 40)[0]
                    mask_interest = (USN_REASON_FILE_CREATE | USN_REASON_DATA_TRUNCATION | USN_REASON_DATA_EXTEND | USN_REASON_FILE_DELETE | USN_REASON_CLOSE)
                    if (reason & mask_interest):
                        ts = struct.unpack_from('<Q', buf, offset + 32)[0]
                        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts/10)
                        if dt > limit_time:
                            fn_len = struct.unpack_from('<H', buf, offset + 56)[0]
                            fn_off = struct.unpack_from('<H', buf, offset + 58)[0]
                            name = buf[offset+fn_off : offset+fn_off+fn_len].decode('utf-16-le', 'ignore')
                            events.append({'time': dt, 'name': name, 'reason': reason})
                    offset += reclen
        except: pass
        finally: ctypes.windll.kernel32.CloseHandle(vol_handle)
        return events

    with open(config.reporte_morph, "w", encoding="utf-8", buffering=1) as report:
        report.write("=== FASE 25: METAMORPHOSIS & GHOST HUNTER ===\n")
        report.write(f"Scan Time: {datetime.datetime.now()}\n")
        
        # Reportar Clones de Metamorfosis si existen
        if hits:
            report.write("\n--- [PART 0] FILE CLONES DETECTED ---\n")
            report.write("\n".join(hits))
            report.write("\n")
        elif target_file:
            report.write("\n[INFO] No clones of the target file found.\n")
            
        report.write(f"YARA Status: {'ACTIVE' if yara_rules else 'OFF'}\n\n")
        
        events = get_usn_events_last_hour()
        report.write("--- [PART A] SIZE ANOMALIES (LAST 1 HOUR) ---\n")
        count_a = 0
        for e in events:
            if config.CANCELAR_ESCANEO: break
            name = e['name']; r = e['reason']; t_str = e['time'].strftime('%H:%M:%S')
            if any(x in name.lower() for x in [".log", ".tmp", ".dat", "ntuser", "$logfile"]): continue
            tags = []
            if r & USN_REASON_DATA_TRUNCATION: tags.append("SHRANK")
            if r & USN_REASON_DATA_EXTEND: tags.append("GREW")
            if r & USN_REASON_FILE_CREATE:
                ent = name_entropy(name.split('.')[0])
                if ent > 4.0 and len(name.split('.')[0]) > 6: tags.append(f"RANDOM NAME")
            if tags:
                report.write(f"[{t_str}] {' + '.join(tags)}: {name}\n")
                count_a += 1
        if count_a == 0: report.write("[OK] Clean.\n")
        
        report.write("\n--- [PART B] GHOST EXECUTABLES (CLOSED/DELETED < 1 HOUR) ---\n")
        report.write("Detects files (.exe/.dll) closed or deleted recently (Panic Key/Bypass).\n")
        suspicious_extensions = (".dll", ".exe", ".tmp", ".bat", ".ps1") 
        count_b = 0
        for e in events:
            name_low = e['name'].lower()
            if not name_low.endswith(suspicious_extensions): continue
            if any(x in name_low for x in ["microsoft", "windows", "defender", "update", "installer", "chrome", "edge", "steam", "discord"]): continue
            r = e['reason']; t_str = e['time'].strftime('%H:%M:%S')
            is_ghost = False; ghost_type = ""
            if r & USN_REASON_FILE_DELETE: is_ghost = True; ghost_type = "DELETED (Panic Key?)"
            elif r & USN_REASON_CLOSE: is_ghost = True; ghost_type = "CLOSED/UNLOADED"
            if is_ghost:
                report.write(f"[{t_str}] [!!!] {ghost_type}: {e['name']}\n")
                count_b += 1
        if count_b == 0: report.write("[OK] No suspicious execution stops found.\n")
        
        report.write("\n--- [PART C] LIVE TOXIC DLLs (CURRENTLY ACTIVE) ---\n")
        GAME_PROCESSES = ["cs2.exe", "csgo.exe", "valorant.exe", "fortniteclient-win64-shipping.exe", "gta5.exe", "fivem.exe", "dota2.exe", "rustclient.exe"]
        SYSTEM_DLLS = {"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "gdi32.dll", "win32u.dll", "wow64.dll", "version.dll", "shlwapi.dll", "ws2_32.dll"}
        WRITABLE_PATHS = ("temp", "appdata", "downloads", "desktop")
        dll_found = 0
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            if config.CANCELAR_ESCANEO or (time.time() - start_time > MAX_TIME): break
            try:
                pname = proc.info["name"].lower()
                if pname not in GAME_PROCESSES: continue
                try: maps = proc.memory_maps()
                except: continue
                for m in maps:
                    path = m.path
                    if not path or not path.lower().endswith(".dll"): continue
                    if os.path.basename(path).lower() in SYSTEM_DLLS: continue
                    if path.lower().startswith((r"c:\windows\system32", r"c:\windows\syswow64", r"c:\program files")): continue
                    score_dll = 0; ev_dll = []
                    if any(w in path.lower() for w in WRITABLE_PATHS): score_dll += 3; ev_dll.append("Risky Path (User Writable)")
                    if yara_rules:
                        try:
                            if yara_rules.match(filepath=path): score_dll += 10; ev_dll.append("YARA MATCH")
                        except: pass
                    if score_dll >= 3:
                        dll_found += 1
                        report.write(f"[TOXIC DLL] {os.path.basename(path)}\n")
                        report.write(f"  In: {pname} (PID {proc.pid})\n")
                        report.write(f"  Path: {path}\n")
                        for e in ev_dll: report.write(f"  - {e}\n")
                        report.write("\n")
            except: pass
        if dll_found == 0: report.write("[OK] No toxic DLLs currently injected.\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_morph)), {'f25': {'active': True}})
    except: pass


# --- F26: STRING CLEANING ---
def fase_string_cleaning(palabras, modo):
    # if config.CANCELAR_ESCANEO: return
    print("[26/26] String Cleaner & USN Resurrection (NATIVE SPEED)...")
    
    # Asegurar ruta
    if not config.reporte_cleaning: config.reporte_cleaning = "String_Cleaner_Detection.txt"
    
    GENEALOGY_RULES = {}; GENERIC_READ = 0x80000000; GENERIC_WRITE = 0x40000000; FILE_SHARE_READ = 0x00000001; FILE_SHARE_WRITE = 0x00000002; OPEN_EXISTING = 3; FILE_ATTRIBUTE_NORMAL = 0x80; FSCTL_QUERY_USN_JOURNAL = 0x000900f4; FSCTL_READ_USN_JOURNAL = 0x000900bb; USN_REASON_FILE_DELETE = 0x00000200; USN_REASON_RENAME_OLD_NAME = 0x00001000; USN_REASON_RENAME_NEW_NAME = 0x00002000
    class USN_JOURNAL_DATA_V0(ctypes.Structure): _fields_ = [("UsnJournalID", ctypes.c_ulonglong), ("FirstUsn", ctypes.c_ulonglong), ("NextUsn", ctypes.c_ulonglong), ("LowestValidUsn", ctypes.c_ulonglong), ("MaxUsn", ctypes.c_ulonglong), ("MaximumSize", ctypes.c_ulonglong), ("AllocationDelta", ctypes.c_ulonglong)]
    class READ_USN_JOURNAL_DATA_V0(ctypes.Structure): _fields_ = [("StartUsn", ctypes.c_ulonglong), ("ReasonMask", ctypes.c_uint), ("ReturnOnlyOnClose", ctypes.c_uint), ("Timeout", ctypes.c_ulonglong), ("BytesToWaitFor", ctypes.c_ulonglong), ("UsnJournalID", ctypes.c_ulonglong)]

    def leer_usn_nativo():
        registros = []
        vol_handle = ctypes.windll.kernel32.CreateFileW(r"\\.\C:", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        if vol_handle == -1: return []
        try:
            journal_data = USN_JOURNAL_DATA_V0(); bytes_ret = ctypes.c_ulong()
            status = ctypes.windll.kernel32.DeviceIoControl(vol_handle, FSCTL_QUERY_USN_JOURNAL, None, 0, ctypes.byref(journal_data), ctypes.sizeof(journal_data), ctypes.byref(bytes_ret), None)
            if not status: return []
            offset = 150 * 1024 * 1024; start_usn = max(0, journal_data.NextUsn - offset)
            read_data = READ_USN_JOURNAL_DATA_V0(); read_data.StartUsn = start_usn; read_data.ReasonMask = 0xFFFFFFFF; read_data.ReturnOnlyOnClose = 0; read_data.Timeout = 0; read_data.BytesToWaitFor = 0; read_data.UsnJournalID = journal_data.UsnJournalID
            buffer_size = 65536; buffer = ctypes.create_string_buffer(buffer_size)
            while True:
                status = ctypes.windll.kernel32.DeviceIoControl(vol_handle, FSCTL_READ_USN_JOURNAL, ctypes.byref(read_data), ctypes.sizeof(read_data), buffer, buffer_size, ctypes.byref(bytes_ret), None)
                if not status or bytes_ret.value < 8: break
                next_usn_blk = struct.unpack_from('<Q', buffer, 0)[0]; read_data.StartUsn = next_usn_blk
                offset_buf = 8
                while offset_buf < bytes_ret.value:
                    if offset_buf + 4 > bytes_ret.value: break
                    reclen = struct.unpack_from('<I', buffer, offset_buf)[0]
                    if reclen == 0: break
                    try:
                        reason = struct.unpack_from('<I', buffer, offset_buf + 40)[0]
                        filename_len = struct.unpack_from('<H', buffer, offset_buf + 56)[0]
                        filename_off = struct.unpack_from('<H', buffer, offset_buf + 58)[0]
                        if (reason & USN_REASON_FILE_DELETE) or (reason & USN_REASON_RENAME_NEW_NAME):
                            ptr_name = offset_buf + filename_off
                            if ptr_name + filename_len <= bytes_ret.value:
                                name_bytes = buffer[ptr_name : ptr_name + filename_len]
                                filename = name_bytes.decode('utf-16-le', errors='ignore')
                                ts_raw = struct.unpack_from('<Q', buffer, offset_buf + 32)[0]
                                dt_obj = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts_raw / 10)
                                tipo = "DELETED" if (reason & USN_REASON_FILE_DELETE) else "RENAMED"
                                registros.append((dt_obj, tipo, filename))
                    except: pass
                    offset_buf += reclen
        except Exception as e: print(f"Error nativo USN: {e}")
        finally: ctypes.windll.kernel32.CloseHandle(vol_handle)
        return registros

    with open(config.reporte_cleaning, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USN JOURNAL FORENSICS (NATIVE): {datetime.datetime.now()} ===\n")
        f.write("Engine: Direct Kernel I/O (No fsutil)\n")
        tools = ["processhacker", "cheatengine", "ksdumper", "everything", "lastactivityview"]
        f.write("\n[1] ACTIVE CLEANING TOOLS:\n")
        try:
            cmd = 'tasklist /fo csv /nh'; proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, text=True); out, _ = proc.communicate(); found = False
            for line in out.splitlines():
                if any(t in line.lower() for t in tools):
                    f.write(f" [!!!] DETECTED: {line.split(',')[0].strip()}\n"); found = True
            if not found: f.write(" [OK] None running.\n")
        except: pass
        f.write("\n[2] RECENTLY DELETED/RENAMED EVIDENCE (Last 150MB of Log):\n")
        f.write(f" Scanning... (This is instant)\n")
        hits = 0
        try:
            eventos = leer_usn_nativo()
            exts_peligrosas = [".exe", ".dll", ".bat", ".ps1", ".pf", ".sys", ".lua", ".cfg"]; ignorar = ["temp", "installer", "update", "cache", "log"]
            for dt, tipo, nombre in eventos:
                nombre_low = nombre.lower()
                if not any(nombre_low.endswith(x) for x in exts_peligrosas): continue
                if any(i in nombre_low for i in ignorar): continue
                is_suspicious = False
                if nombre_low.endswith(".pf"): is_suspicious = True
                if any(p in nombre_low for p in palabras): is_suspicious = True
                if modo == "Analizar Todo" and ".exe" in nombre_low: is_suspicious = True
                if is_suspicious:
                    tag = "[!!!]" if nombre_low.endswith(".pf") else "[INFO]"
                    f.write(f" {tag} [{dt.strftime('%H:%M:%S')}] {tipo}: {nombre}\n"); hits += 1
            if hits == 0: f.write(" [OK] No suspicious file deletions found in recent journal.\n")
            else: f.write(f"\n [ALERTA] Found {hits} suspicious events.\n")
        except Exception as e: 
            f.write(f" [ERROR] Failed to read USN: {e}\n"); f.write(" * Ensure you are running as ADMINISTRATOR.\n")

    # INTEGRACIÓN: Actualizar HTML
    try: generar_reporte_html(os.path.dirname(os.path.abspath(config.reporte_cleaning)), {'f26': {'active': True}})
    except: pass
    
def fase_usn_journal(palabras, modo):
    if config.CANCELAR_ESCANEO: return
    print(f"[27/27] USN Journal: 'El Ojo de Dios' (Detectando Borrados)...")
    
    config.reporte_usn = asegurar_ruta_reporte("USN_Journal_Evidence.txt")
    
    # Extensiones peligrosas a vigilar
    EXT_PELIGROSAS = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.py', '.tmp']
    
    now = datetime.datetime.now()
    
    with open(config.reporte_usn, "w", encoding="utf-8", buffering=1) as f:
        f.write(f"=== USN JOURNAL FORENSICS: {now.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write("Target: Archivos ELIMINADOS o RENOMBRADOS recientemente.\n")
        f.write("NOTA: Este registro es de bajo nivel NTFS. Es casi imposible de falsificar.\n\n")
        f.write(f"{'TIMESTAMP':<20} | {'ACCIÓN':<15} | {'ARCHIVO':<40} | DETALLES\n")
        f.write("-" * 100 + "\n")

        try:
            # Usamos fsutil para leer el journal del disco C:
            # Esto requiere Admin, pero Scanneler ya lo pide.
            # Leemos los últimos datos (no todo el historial porque es gigante)
            cmd = ['fsutil', 'usn', 'readjournal', 'C:', 'csv']
            
            # Ejecutamos y leemos línea por línea
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='ignore')
            
            # Recopilamos las últimas líneas (ej: últimas 5000 operaciones) para no saturar
            # En un caso real forense, leeríamos todo, pero para una app rápida, leemos el buffer reciente.
            lineas_relevantes = []
            
            # Leemos la salida en tiempo real
            count = 0
            MAX_LINES = 10000  # Analizar las últimas 10k operaciones del disco
            
            # fsutil devuelve datos antiguos primero, así que guardamos y procesamos al revés o filtramos por fecha si pudiéramos
            # Truco: Leeremos todo y luego filtraremos.
            output_lines = proc.stdout.readlines()
            
            # Invertimos para ver lo más reciente primero
            for line in reversed(output_lines):
                if count >= MAX_LINES: break
                
                parts = line.split(',')
                if len(parts) < 5: continue
                
                # Formato fsutil csv: 
                # Offset, FileID, ParentID, USN, TimeStamp, Reason, SourceInfo, SecurityId, FileAttributes, FileName
                # A veces varía según versión de Windows, buscamos dinámicamente
                
                try:
                    # Buscamos el nombre del archivo (suele ser el último campo o anteúltimo)
                    filename = parts[-1].strip()
                    reasons = parts[5].strip() # Reason flag
                    timestamp_str = parts[4].strip() # Date
                    
                    # Filtro 1: Solo extensiones peligrosas
                    nombre_lower = filename.lower()
                    if not any(nombre_lower.endswith(ext) for ext in EXT_PELIGROSAS):
                        continue

                    # Filtro 2: Ignorar archivos temporales de Windows/Navegadores (Ruido)
                    if any(x in nombre_lower for x in ["chrome", "edge", "discord", "update", "log", "temp", "cache"]):
                        # A menos que tenga palabra clave de cheat
                        if not any(p in nombre_lower for p in palabras):
                            continue

                    # Filtro 3: Detectar eventos CRÍTICOS
                    accion = "MODIFICADO"
                    es_sospechoso = False
                    
                    if "0x80000004" in reasons or "FILE_DELETE" in reasons:
                        accion = "!!! ELIMINADO"
                        es_sospechoso = True
                    elif "0x00002000" in reasons or "RENAME_NEW_NAME" in reasons:
                        accion = "RENOMBRADO"
                        es_sospechoso = True
                    elif "0x00001000" in reasons or "RENAME_OLD_NAME" in reasons:
                        accion = "RENOMBRADO (OLD)"
                    elif "0x00000100" in reasons or "FILE_CREATE" in reasons:
                        accion = "CREADO"
                    
                    # Si no es Delete/Create/Rename, lo saltamos para limpiar reporte
                    if accion == "MODIFICADO": continue

                    # CHEQUEO FINAL: Palabras Clave o Modo Todo
                    hit_palabra = any(p in nombre_lower for p in palabras)
                    
                    if hit_palabra:
                        tag = "[MATCH]"
                        es_sospechoso = True
                    else:
                        tag = ""

                    if es_sospechoso or (modo == "Analizar Todo" and accion == "!!! ELIMINADO"):
                        f.write(f"{timestamp_str:<20} | {accion:<15} | {filename:<40} | {tag}\n")
                        count += 1
                        
                except: continue

            if count == 0:
                f.write("\n[OK] No se detectaron borrados recientes de archivos ejecutables sospechosos.\n")
                
        except Exception as e:
            f.write(f"\n[ERROR] No se pudo leer el USN Journal: {e}\n")
            f.write("Asegúrate de ejecutar Scanneler como ADMINISTRADOR.\n")

    # Integración HTML
    try: generar_reporte_html(os.path.dirname(config.reporte_usn), {'f27': {'active': True}})
    except: pass