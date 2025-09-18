import os
import zipfile

PATCHRAW_DIR = "patchraw"
PATCH_DIR = "patch"
PATCH_NAME = "patch.zip"

def create_patch():
    os.makedirs(PATCH_DIR, exist_ok=True)
    patch_path = os.path.join(PATCH_DIR, PATCH_NAME)

    with zipfile.ZipFile(patch_path, "w", zipfile.ZIP_DEFLATED) as patch_zip:
        for root, _, files in os.walk(PATCHRAW_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, PATCHRAW_DIR)  # relative paths im ZIP
                patch_zip.write(file_path, arcname)

    print(f"✅ Patch erstellt: {patch_path}")

if __name__ == "__main__":
    create_patch()
