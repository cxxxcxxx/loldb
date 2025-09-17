
from updater import check_for_update, download_patch, apply_patch
from tkinter import messagebox, Tk
import sys

# Prüfe Update beim Start
update_available, new_version = check_for_update()
if update_available:
    root = Tk()
    root.withdraw()  # kein leeres Fenster
    if messagebox.askokcancel("Update verfügbar", f"Neue Version {new_version} verfügbar. Patch jetzt installieren?"):
        if download_patch() and apply_patch():
            # Lokale version.txt aktualisieren
            with open("version.txt", "w") as f:
                f.write(new_version)
            messagebox.showinfo("Update", "Patch erfolgreich installiert! Bitte Programm neu starten.")
            sys.exit(0)
        else:
            messagebox.showerror("Fehler", "Patch konnte nicht heruntergeladen oder angewendet werden.")
    root.destroy()




import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g, jsonify, abort, flash
import json

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB_NAME = "wiki.db"
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

login_manager = LoginManager(app)
login_manager.login_view = "login"  # Endpoint name for unauthenticated redirects


# ----------------- Helfer -----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db


def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)

    if query.strip().lower().startswith("select"):
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    else:
        db.commit()
        cur.close()
        return None







def _normalize_item_to_static_path(name):
    """
    Wandelt einen rohen Item-Namen oder Pfad in den korrekten Static-Pfad um.
    Beispiele:
        "rageblade.png" -> "items/ap/rageblade.png"
        "uploads/custom_item.png" -> "uploads/custom_item.png"
    """
    if not name:
        return None

    rn = str(name).replace("\\", "/").lstrip("/")

    if rn.startswith(("uploads/", "items/", "runes/")):
        return rn
    elif "/" in rn:
        return f"items/{rn}"
    else:
        # default fallback, z. B. nur Dateiname
        return f"uploads/{rn}"


def _normalize_rune_filename(category, filename):
    """
    Normalisiert Runen-Pfade für Keystone, Subrune und Smallrune.
    category: keystone | subrune | smallrune
    filename: z. B. "lethaltempo.png"
    Rückgabe: "runes/keystone/lethaltempo.png"
    """
    if not category or not filename:
        return None

    # Entferne evtl. führende Pfad-Teile
    fn = str(filename).replace("\\", "/").split("/")[-1]

    return f"runes/{category}/{fn}"


def build_category_tree():
    """Liefert Liste von Dicts: {id,name,parent_id,children: [...]}. alphabetisch sortiert"""
    rows = query_db("SELECT id, name, parent_id FROM categories ORDER BY name COLLATE NOCASE ASC")
    cats = {}
    for r in rows:
        cats[r["id"]] = {"id": r["id"], "name": r["name"], "parent_id": r["parent_id"], "children": []}
    root = []
    for c in cats.values():
        if c["parent_id"] is None:
            root.append(c)
        else:
            parent = cats.get(c["parent_id"])
            if parent:
                parent["children"].append(c)
            else:
                # wenn parent nicht existiert, treat as root
                root.append(c)
    # sort children alphabetically
    for c in root:
        c["children"].sort(key=lambda x: x["name"].lower())
    root.sort(key=lambda x: x["name"].lower())
    return root


def get_categories(parent_id=None):
    """Gibt sqlite3.Rows zurück (für Fälle wo Code SELECT * erwartet)."""
    if parent_id is None:
        return query_db("SELECT * FROM categories WHERE parent_id IS NULL ORDER BY name COLLATE NOCASE ASC")
    return query_db("SELECT * FROM categories WHERE parent_id=? ORDER BY name COLLATE NOCASE ASC", (parent_id,))


def save_article(title, category_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO articles (title, category_id) VALUES (?, ?)", (title, category_id))
    art_id = c.lastrowid
    conn.commit()
    conn.close()
    return art_id


def save_block(article_id, block):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO article_blocks (article_id, type, content, position, extra) VALUES (?, ?, ?, ?, ?)",
        (article_id, block.get("type"), block.get("content"), block.get("position", 0), block.get("extra"))
    )
    conn.commit()
    conn.close()


def get_article(article_id):
    return query_db("SELECT * FROM articles WHERE id=?", (article_id,), one=True)


def get_blocks_for_article(article_id):
    return query_db(
        "SELECT id, article_id, type, content, extra FROM article_blocks WHERE article_id=? ORDER BY position ASC",
        (article_id,)
    )


def get_blocks_for_edit(article_id):
    return query_db(
        "SELECT id, type, content, extra FROM article_blocks WHERE article_id=? ORDER BY position ASC",
        (article_id,)
    )


# ----------------- DB initialisieren / migration sicher -----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Tabelle categories (erstellt falls nicht vorhanden)
    c.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    """)
    # stelle sicher, dass parent_id existiert
    cols = [row[1] for row in c.execute("PRAGMA table_info(categories)").fetchall()]
    if "parent_id" not in cols:
        try:
            c.execute("ALTER TABLE categories ADD COLUMN parent_id INTEGER")
        except Exception:
            pass

    # andere Tabellen
    c.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category_id INTEGER,
            FOREIGN KEY(category_id) REFERENCES categories(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS article_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER,
            type TEXT,
            content TEXT,
            position INTEGER,
            extra TEXT,
            FOREIGN KEY(article_id) REFERENCES articles(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS item_builds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER,
            block_id INTEGER,
            item_name TEXT NOT NULL,
            position INTEGER,
            FOREIGN KEY(article_id) REFERENCES articles(id),
            FOREIGN KEY(block_id) REFERENCES article_blocks(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ----------------- Flask-Login User -----------------
class User(UserMixin):
    def __init__(self, id_, username, is_admin):
        self.id = id_
        self.username = username
        self.is_admin = is_admin


@login_manager.user_loader
def load_user(user_id):
    u = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if u:
        return User(u["id"], u["username"], bool(u["is_admin"]))
    return None


# ----------------- Globale Kategorien (für Sidebar) -----------------
@app.before_request
def load_categories():
    g.categories_global = build_category_tree()


# ----------------- API: Items (für Editor) -----------------
@app.route("/api/items")
def api_items():
    base = os.path.join(app.root_path, "static", "items")
    cats = {}
    if os.path.exists(base):
        for cat in os.listdir(base):
            cat_path = os.path.join(base, cat)
            if os.path.isdir(cat_path):
                files = [f for f in os.listdir(cat_path) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))]
                files.sort(key=lambda x: x.lower())
                cats[cat] = files
    return jsonify(cats)


# ----------------- API: Runes (neues) -----------------
@app.route("/api/runes")
def api_runes():
    """
    Liefert die Dateien in static/runes/<category> als JSON.
    Ordnernamen werden exakt so belassen.
    """
    base = os.path.join(app.root_path, "static", "runes")
    cats = {}
    if os.path.exists(base):
        for cat in os.listdir(base):
            cat_path = os.path.join(base, cat)
            if os.path.isdir(cat_path):
                files = [f for f in os.listdir(cat_path) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))]
                files.sort(key=lambda x: x.lower())
                cats[cat] = files

    # Ensure common keys exist (not renaming anything)
    for k in ("keystone", "subrune", "smallrune"):
        if k not in cats:
            cats[k] = []

    return jsonify(cats)


# ----------------- Login / Logout -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            login_user(User(user["id"], user["username"], bool(user["is_admin"])))
            flash("Erfolgreich eingeloggt.")
            return redirect(url_for("index"))
        flash("Login fehlgeschlagen")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Du wurdest ausgeloggt.")
    return redirect(url_for("index"))


# ----------------- Routen -----------------
@app.route("/")
def index():
    # Nutze g.categories_global / index template zeigt Hauptkategorien
    articles = query_db("SELECT * FROM articles")
    return render_template("index.html", articles=articles)


@app.route("/category/<int:cat_id>")
def show_category(cat_id):
    category = query_db("SELECT * FROM categories WHERE id=?", (cat_id,), one=True)
    if not category:
        return "Kategorie nicht gefunden", 404
    # alphabetisch gruppiert nach Anfangsbuchstaben
    articles_raw = query_db("SELECT * FROM articles WHERE category_id=? ORDER BY title COLLATE NOCASE ASC", (cat_id,))
    grouped_articles = {}
    for art in articles_raw:
        first = art["title"][0].upper() if art["title"] else "#"
        grouped_articles.setdefault(first, []).append(art)
    return render_template("category.html", category=category, grouped_articles=grouped_articles)


@app.route("/add_category", methods=["GET", "POST"])
@login_required
def add_category():
    if not current_user.is_admin:
        abort(403)
    if request.method == "POST":
        name = request.form.get("name")
        parent_id = request.form.get("parent_id") or None
        if name:
            query_db("INSERT INTO categories (name, parent_id) VALUES (?, ?)", (name, parent_id))
            return redirect(url_for("index"))
    main_cats = query_db("SELECT * FROM categories WHERE parent_id IS NULL ORDER BY name COLLATE NOCASE ASC")
    return render_template("add_category.html", categories=main_cats)


@app.route("/add_article", methods=["GET", "POST"])
@login_required
def add_article():
    if not current_user.is_admin:
        abort(403)
    if request.method == "POST":
        title = request.form.get("title")
        category_id = request.form.get("category")
        blocks_json = request.form.get("blocks_json", "[]")
        art_id = save_article(title, category_id)

        try:
            blocks = json.loads(blocks_json)
        except Exception:
            blocks = []

        for idx, block in enumerate(blocks):
            extra = None
            if block.get("type") == "rune_grid":
                extra = json.dumps(block.get("runes", {}))
            elif block.get("type") == "item_grid":
                extra = json.dumps(block.get("items", []))
            else:
                extra = block.get("extra")
            save_block(art_id, {
                "type": block.get("type"),
                "content": block.get("content"),
                "position": idx,
                "extra": extra
            })
        return redirect(url_for("article", art_id=art_id))
    return render_template("add_article.html", blocks_data=[])



@app.route("/article/edit/<int:art_id>", methods=["GET", "POST"])
@login_required
def edit_article(art_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

    # Artikel abrufen
    article = query_db("SELECT * FROM articles WHERE id = ?", (art_id,), one=True)
    if not article:
        abort(404)

    db = get_db()  # DB-Verbindung

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category_id = request.form.get("category")
        blocks_json = request.form.get("blocks_json", "[]")

        # Prüfen, ob JSON korrekt ist
        try:
            blocks = json.loads(blocks_json)
        except Exception:
            flash("Fehler beim Speichern: Ungültige Block-Daten", "danger")
            return redirect(request.url)

        # Artikel aktualisieren
        db.execute(
            "UPDATE articles SET title = ?, category_id = ? WHERE id = ?",
            (title, category_id, art_id)
        )

        # Alte Blöcke löschen und neue speichern
        db.execute("DELETE FROM article_blocks WHERE article_id=?", (art_id,))
        for idx, block in enumerate(blocks):
            extra = None
            if block.get("type") == "rune_grid":
                extra = json.dumps(block.get("runes", {}))
            elif block.get("type") == "item_grid":
                extra = json.dumps(block.get("items", []))
            else:
                extra = block.get("extra")
            db.execute(
                "INSERT INTO article_blocks (article_id, type, content, position, extra) VALUES (?, ?, ?, ?, ?)",
                (art_id, block.get("type"), block.get("content"), idx, extra)
            )
        db.commit()

        flash("Artikel erfolgreich gespeichert", "success")
        return redirect(url_for("article", art_id=art_id))

    # --- GET: Blöcke für Editor vorbereiten ---
    blocks_rows = get_blocks_for_edit(art_id)
    blocks_data = []

    # Lade alle item_builds für diesen Artikel
    all_item_builds = query_db(
        "SELECT * FROM item_builds WHERE article_id=? ORDER BY position ASC", (art_id,)
    )

    for r in blocks_rows:
        try:
            extra = json.loads(r["extra"]) if r["extra"] else None
        except Exception:
            extra = r["extra"]

        block = {
            "id": r["id"],
            "type": r["type"],
            "content": r["content"],
            "extra": extra
        }

        # --- Item Grid ---
        if r["type"] == "item_grid":
            # Lade Items aus DB für diesen Block
            rows = [ib for ib in all_item_builds if ib["block_id"] == r["id"]]
            items = []
            for row in rows:
                items.append({
                    "id": row["id"],  # DB-ID für Löschen/Editieren
                    "path": _normalize_item_to_static_path(row["item_name"])
                })
            block["items"] = items

        # --- Rune Grid ---
        if r["type"] == "rune_grid":
            block["runes"] = extra if isinstance(extra, dict) else {"keystone": [], "subrune": [], "smallrune": []}

        blocks_data.append(block)

    return render_template("edit_article.html", article=article, blocks_data=blocks_data)










# ----------------- Helper: normalize entries for article view -----------------
def _normalize_item_to_static_path(entry):
    """
    entry may be:
     - a dict (from editor) like {"id": "...", "img":"items/.../file.png", ...}
     - a string like "items/cat/file.png" or "uploads/xxx.png" or "file.png"
    returns a string like "items/cat/file.png" or "uploads/file.png"
    """
    if entry is None:
        return None
    # if dict-like (after JSON load), try to extract best candidate
    if isinstance(entry, dict):
        for key in ("static_path", "img", "path", "file", "filename", "id", "name"):
            if key in entry and entry[key]:
                candidate = str(entry[key])
                break
        else:
            candidate = None
    else:
        candidate = str(entry)

    if not candidate:
        return None

    candidate = candidate.replace("\\", "/").lstrip("/")
    # strip leading 'static/' or '/static/'
    if candidate.startswith("static/"):
        candidate = candidate[len("static/"):]
    if candidate.startswith("/static/"):
        candidate = candidate[len("/static/"):]
    # now candidate might be "uploads/..", "items/..", "runes/..", or "cat/file.png"
    if candidate.startswith("uploads/") or candidate.startswith("items/") or candidate.startswith("runes/"):
        return candidate
    # if looks like path with slash, assume items/
    if "/" in candidate:
        return f"items/{candidate}"
    # fallback -> uploads
    return f"uploads/{candidate}"


def _normalize_rune_filename(cat, fname):
    """
    cat: target normalized category name used in static folder (keystone/subrune/smallrune)
    fname: could be "keystone/foo.png" or "foo.png" or "/static/runes/keystone/foo.png"
    returns "runes/<cat>/<filename>"
    """
    if fname is None:
        return None
    fstr = str(fname).replace("\\", "/").lstrip("/")
    # remove any leading static/ or /static/
    if fstr.startswith("static/"):
        fstr = fstr[len("static/"):]
    if fstr.startswith("/static/"):
        fstr = fstr[len("/static/"):]
    # if already begins with runes/...
    if fstr.startswith("runes/"):
        parts = fstr.split("/")
        fname_only = parts[-1]
    else:
        # if contains slash, assume last part is filename
        if "/" in fstr:
            fname_only = fstr.split("/")[-1]
        else:
            fname_only = fstr
    return f"runes/{cat}/{fname_only}"


@app.route("/article/<int:art_id>")
def article(art_id):
    article = get_article(art_id)
    if not article:
        return "Artikel nicht gefunden", 404

    blocks = get_blocks_for_article(art_id)

    all_build_items = query_db(
        "SELECT id, article_id, block_id, item_name "
        "FROM item_builds WHERE article_id=? ORDER BY position ASC",
        (art_id,)
    )

    build_items_by_block = {}

    for block in blocks:
        block_id = block["id"]

        # --- Item Grid ---
        if block["type"] == "item_grid":
            rows = [r for r in all_build_items if r["block_id"] == block_id]
            items = []

            if rows:
                for r in rows:
                    raw_name = r["item_name"]
                    rn = str(raw_name).replace("\\", "/").lstrip("/")

                    if rn.startswith("uploads/") or rn.startswith("items/") or rn.startswith("runes/"):
                        static_path = rn
                    elif "/" in rn:
                        static_path = f"items/{rn}"
                    else:
                        static_path = f"uploads/{rn}"

                    items.append(static_path)

            else:
                extra = block["extra"]
                if extra:
                    try:
                        parsed = json.loads(extra)
                        if isinstance(parsed, list):
                            for p in parsed:
                                sp = _normalize_item_to_static_path(p)
                                if sp:
                                    items.append(sp)
                    except Exception:
                        try:
                            parts = [p.strip() for p in str(extra).split(",") if p.strip()]
                            for p in parts:
                                sp = _normalize_item_to_static_path(p)
                                if sp:
                                    items.append(sp)
                        except Exception:
                            items = []

            build_items_by_block[block_id] = items

        # --- Rune Grid ---
        elif block["type"] == "rune_grid":
            grouped = {"keystone": [], "subrune": [], "smallrune": []}
            extra = block["extra"]

            if extra:
                try:
                    parsed = json.loads(extra)
                    if isinstance(parsed, dict):
                        for cat_key, arr in parsed.items():
                            key_l = str(cat_key).lower()

                            if key_l.startswith("mini") or "small" in key_l:
                                cat = "smallrune"
                            elif "key" in key_l or key_l == "keystone":
                                cat = "keystone"
                            elif "sub" in key_l:
                                cat = "subrune"
                            else:
                                cat = cat_key if cat_key in grouped else None

                            if cat is None or not isinstance(arr, (list, tuple)):
                                continue

                            for fname in arr:
                                try:
                                    static_path = _normalize_rune_filename(cat, fname)
                                    grouped[cat].append(static_path)
                                except Exception:
                                    continue
                except Exception:
                    grouped = {"keystone": [], "subrune": [], "smallrune": []}

            build_items_by_block[block_id] = grouped

    return render_template(
        "article.html",
        article=article,
        blocks=blocks,
        build_items_by_block=build_items_by_block
    )



@app.route("/add_item_build/<int:block_id>", methods=["GET", "POST"])
@login_required
def add_item_build(block_id):
    if not current_user.is_admin:
        abort(403)
    block = query_db("SELECT id, article_id, type FROM article_blocks WHERE id=?", (block_id,), one=True)
    if not block:
        return "Block nicht gefunden", 404
    art_id = block["article_id"]
    item_categories = ["ad", "ap", "tank"]
    items_by_category = {}
    for cat in item_categories:
        folder = os.path.join("static", "items", cat)
        items_by_category[cat] = [f for f in os.listdir(folder) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))] if os.path.exists(folder) else []
    if request.method == "POST":
        item_name = request.form.get("item_name")
        if item_name:
            pos = query_db("SELECT COUNT(*) FROM item_builds WHERE block_id=?", (block_id,), one=True)[0]
            query_db("INSERT INTO item_builds (article_id, block_id, item_name, position) VALUES (?, ?, ?, ?)",
                     (art_id, block_id, item_name, pos))
        return redirect(url_for("edit_article", art_id=art_id))
    return render_template("add_item_build.html", block=block, items_by_category=items_by_category)


@app.route("/delete_item/<int:item_id>", methods=["POST"])
@login_required
def delete_item(item_id):
    if not current_user.is_admin:
        abort(403)
    query_db("DELETE FROM item_builds WHERE id=?", (item_id,))
    return ('', 204)


# ----------------- Image Upload Endpoint -----------------
@app.route("/upload_image", methods=["POST"])
@login_required
def upload_image():
    # only admins allowed to upload images (editor actions)
    if not current_user.is_admin:
        abort(403)
    if "file" not in request.files:
        return {"error": "no file part"}, 400
    file = request.files["file"]
    if file.filename == "":
        return {"error": "no selected file"}, 400
    if not allowed_file(file.filename):
        return {"error": "file type not allowed"}, 400

    filename = secure_filename(file.filename)
    upload_folder = app.config.get("UPLOAD_FOLDER", os.path.join("static", "uploads"))
    upload_path = os.path.join(app.root_path, upload_folder)
    os.makedirs(upload_path, exist_ok=True)

    base, ext = os.path.splitext(filename)
    counter = 0
    candidate = filename
    while os.path.exists(os.path.join(upload_path, candidate)):
        counter += 1
        candidate = f"{base}_{counter}{ext}"
    filename = candidate

    save_path = os.path.join(upload_path, filename)
    file.save(save_path)

    if PIL_AVAILABLE:
        try:
            thumb_dir = os.path.join(upload_path, "thumbs")
            os.makedirs(thumb_dir, exist_ok=True)
            thumb_path = os.path.join(thumb_dir, filename)
            with Image.open(save_path) as im:
                im.thumbnail((800, 800))
                im.save(thumb_path)
        except Exception:
            pass

    relative = os.path.join("uploads", filename).replace("\\", "/")
    return {"filename": relative}

@app.template_filter("imgsrc")
def imgsrc_filter(val):
    if not val:
        return ""
    val = str(val)
    if val.startswith(("keystone/", "subrune/", "smallrune/")):
        return f"/static/runes/{val}"
    if val.startswith(("items/", "uploads/")):
        return f"/static/{val}"
    return f"/static/uploads/{val}"


@app.route("/rune_test")
def rune_test():
    return render_template("rune_test.html")


if __name__ == "__main__":
    app.run(debug=True)
