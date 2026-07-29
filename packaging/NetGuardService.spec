# -*- mode: python ; coding: utf-8 -*-
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
PROJECT = os.path.join(ROOT, 'CNLabProject')

a = Analysis(
    [os.path.join(PROJECT, 'service.py')],
    pathex=[PROJECT],
    binaries=[],
    datas=[(os.path.join(PROJECT, 'templates'), 'templates')],
    hiddenimports=['win32timezone', 'servicemanager'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetGuardService',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name='NetGuardService')