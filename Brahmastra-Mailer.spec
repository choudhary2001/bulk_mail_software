# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Brahmastra-Mailer.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/Administrator/AppData/Local/Programs/Python/Python312/python3.dll', '.'), ('w/wkhtmltopdf.exe', 'w'), ('w/wkhtmltoimage.exe', 'w'), ('images', 'images'), ('gmass.txt', '.'), ('test_password.csv', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Brahmastra-Mailer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['images\\logo.ico'],
)
