# -*- mode: python ; coding: utf-8 -*-
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
PROJECT = os.path.join(ROOT, 'CNLabProject')

a = Analysis(
    [os.path.join(PROJECT, 'desktop.py')],
    pathex=[PROJECT],
    binaries=[],
    datas=[],
    hiddenimports=['win32timezone'],
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
    name='NetGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name='NetGuard')