# `app` is supplied by the host framework in this intentionally minimal
# fixture; keeping it unresolved exercises the analyzer's external-symbol path.

import db
from auth import require_auth
from flask import request


@app.route("/dashboard")  # noqa: F821  (host framework symbol)
@require_auth
def dashboard():
    return db.get_user(request.args.get("user_id"))


@app.route("/login", methods=["POST"])  # noqa: F821  (host framework symbol)
def login():
    return "ok"


@app.route("/admin/users", methods=["POST"])  # noqa: F821  (host framework symbol)
@require_auth
def admin_create_user():
    return db.create_user(request.json)
