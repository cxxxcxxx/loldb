import os
import zipfile
import requests
from tkinter import messagebox, Tk

# Config
GITHUB_ZIP_URL = "https://github.com/DEIN_USERNAME/DEIN_REPO/archive/refs/heads/main.zip"
VERSION_FILE = "version.txt"

def get_local_version():
    if not os.path.exists(VERSION_FILE):
        return "0.0.0.0"
    with open(VERSION_FILE, "r") as f:
        return f.read().strip()

def set_local_version(version):
    with open(VERSION_FILE, "w") as f:
        f.write(version)

def check_for_update():
    local_version = get_local_version()

    # Lade online version.txt aus GitHub (roh)
    try:
        raw_version_url = "https://raw.githubusercontent.com/DEIN_USERNAME/DEIN_REPO/main/version.txt"
        r = requests.get(raw_version_url)
        r.raise_for_status()
        online_version = r.text.strip()
    except Exception as e:
        print("Fehler beim Prüfen der Version:", e)
        return False

    if online_version > local_version:
        # Update verfügbar
        root = Tk()
        root.withdraw()  # Kein Hauptfenster
        if messagebox.askokcancel("Update verfügbar", f"Neue Version {online_version} verfügbar.\nJetzt updaten?"):
            download_and_install_patch()
            set_local_version(online_version)
            messagebox.showinfo("Update", "Update erfolgreich installiert. Bitte App neu starten.")
        root.destroy()
        return True
    return False

def download_and_install_patch():
    try:
        r = requests.get(GITHUB_ZIP_URL)
        r.raise_for_status()
        zip_path = "update_patch.zip"
        with open(zip_path, "wb") as f:
            f.write(r.content)

        # Entpacken
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(".")  # Entpackt in den aktuellen Ordner

        os.remove(zip_path)
        print("Patch installiert.")
    except Exception as e:
        print("Fehler beim Patchen:", e)
