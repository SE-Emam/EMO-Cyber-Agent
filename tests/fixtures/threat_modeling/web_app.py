from flask import request
from auth import require_auth
import db


@app.route("/dashboard")
@require_auth
def dashboard():
    return db.get_user(request.args.get("user_id"))


@app.route("/login", methods=["POST"])
def login():
    return "ok"


@app.route("/admin/users", methods=["POST"])
@require_auth
def admin_create_user():
    return db.create_user(request.json)
