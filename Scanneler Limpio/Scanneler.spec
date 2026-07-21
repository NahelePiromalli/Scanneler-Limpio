# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

customtkinter_datas = collect_data_files('customtkinter')

datas_files = [
    ('Scanneler.png', '.'),
    ('Scanneler.ico', '.'),
    ('reglas_scanneler.yar', '.'),
    ('lista.txt', '.')
] + customtkinter_datas

hidden_imports = ['yara', 'customtkinter', 'PIL', 'requests', 'psutil', 'winreg', 'ctypes'] + collect_submodules('customtkinter')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Scanneler',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    uac_admin=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='Scanneler.ico',
)
