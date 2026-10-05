def require_auth(fn):
    return fn


def login(username, password):
    user = find_user(username)
    if user and user.check_password(password):
        return issue_token(user)
    return None
