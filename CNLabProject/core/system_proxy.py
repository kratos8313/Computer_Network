import subprocess

def enable_proxy():
    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"
    ])

    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyServer", "/t", "REG_SZ", "/d", "127.0.0.1:8080", "/f"
    ])


def disable_proxy():
    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"
    ])