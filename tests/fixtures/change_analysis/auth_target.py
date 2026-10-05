def require_auth(fn):
    return fn


def login(username, password, next_url=None):
    user = find_user(username)
    if user and user.check_password(password):
        return redirect(next_url or dashboard(user))
    return None
