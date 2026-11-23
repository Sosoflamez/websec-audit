"""
Mini-application Flask volontairement vulnérable, utilisée UNIQUEMENT en
local (127.0.0.1) pour valider le fonctionnement des scripts de
websec-audit sur une cible que nous contrôlons entièrement.

Ne pas exposer ce serveur sur un réseau public.
"""
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

FAKE_DB = {
    "invoices": {
        "100": {"owner": "user1", "amount": 42},
        "101": {"owner": "user2", "amount": 99},
    }
}

LOGIN_PAGE = """
<html><body>
<form method="post" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit">
</form>
</body></html>
"""

SEARCH_PAGE = """
<html><body>
<form method="get" action="/search">
  <input type="text" name="q">
  <input type="submit">
</form>
<p>Resultat: {result}</p>
</body></html>
"""


@app.route("/")
def home():
    resp = make_response("<html><body>Accueil app de test</body></html>")
    resp.headers["Server"] = "TestServer/1.0"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_PAGE
    # Pas de vrai check, juste pour simuler succès/echec + cookie de session fixe
    resp = make_response("OK" if request.form.get("password") else "FAIL", 200)
    resp.set_cookie("session_id", "fixed-session-id-not-regenerated")
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Reflet volontairement NON échappé pour simuler une XSS réfléchie,
    # et une "erreur SQL" simulée pour simuler une détection SQLi.
    if "'" in q:
        return "Error: SQL syntax error near '" + q + "' (simulated, no real DB)", 500
    return SEARCH_PAGE.format(result=q)


@app.route("/api/invoices/<invoice_id>")
def invoice(invoice_id):
    # Volontairement SANS vérification de propriétaire -> IDOR simulé
    data = FAKE_DB["invoices"].get(invoice_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/admin")
def admin():
    # Volontairement accessible sans auth -> finding attendu
    return jsonify({"users": ["user1", "user2"]})


@app.route("/.env")
def dotenv():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=\"abcd1234efgh5678ijkl\"\n", 200


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400
    # Volontairement permissif : accepte tout
    return jsonify({"status": "uploaded", "filename": f.filename, "url": f"/uploads/{f.filename}"}), 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5151)
