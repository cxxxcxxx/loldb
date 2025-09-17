import os
import requests
import zipfile

UPDATE_URL = "https://github.com/cxxxcxxx/loldb/releases/latest/download/patch.zip"
VERSION_FILE = "version.txt"
LOCAL_VERSION_FILE = VERSION_FILE

def get_local_version():
    if os.path.exists(LOCAL_VERSION_FILE):
        with open(LOCAL_VERSION_FILE, "r") as f:
            return f.read().strip()
    return "0.0.0"

def get_remote_version():
    # Version aus GitHub abrufen
    try:
        r = requests.get("https://raw.githubusercontent.com/cxxxcxxx/loldb/main/version.txt")
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return None

def download_patch():
    try:
        r = requests.get(UPDATE_URL, stream=True)
        if r.status_code == 200:
            with open("patch.zip", "wb") as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            return True
    except Exception as e:
        print("Download fehlgeschlagen:", e)
    return False

def apply_patch():
    if not os.path.exists("patch.zip"):
        return False
    try:
        with zipfile.ZipFile("patch.zip", "r") as zip_ref:
            zip_ref.extractall(".")  # alles überschreiben
        os.remove("patch.zip")
        return True
    except Exception as e:
        print("Patch konnte nicht angewendet werden:", e)
        return False

def check_for_update():
    local = get_local_version()
    remote = get_remote_version()
    if remote is None:
        return False, None
    if local != remote:
        return True, remote
    return False, None
