"""Compatibility entry point for the former Tkinter interface.

The supported management interface is now the authenticated local web dashboard.
"""
from main import main

if __name__ == '__main__':
    raise SystemExit(main())
