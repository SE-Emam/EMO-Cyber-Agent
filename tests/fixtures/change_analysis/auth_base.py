def require_auth(fn):
    return fn


def login(username, password):
    user = find_user(username)  # noqa: F821  (host-provided collaborator)
    if user and user.check_password(password):
        return issue_token(user)  # noqa: F821  (host-provided collaborator)
    return None
