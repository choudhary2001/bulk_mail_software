# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Brahmastra-Mailer.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/David/Desktop/brahmastra/bulk_mail_software/w/wkhtmltopdf.exe', 'w'), ('C:/Users/David/Desktop/brahmastra/bulk_mail_software/w/wkhtmltoimage.exe', 'w'), ('C:/Users/David/Desktop/brahmastra/bulk_mail_software/images/logo.ico', '.'), ('C:/Users/David/Desktop/brahmastra/bulk_mail_software/gmass.txt', '.'), ('C:/Users/David/Desktop/brahmastra/bulk_mail_software/test_password.csv', '.'), ('C:/Users/David/Desktop/brahmastra/bulk_mail_software/images', 'images')],
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
)
