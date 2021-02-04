from functools import wraps

global current_user


def get_current_user(user):
    global current_user
    current_user = user


def has_roles(*roles, children=True):
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if not current_user:
                return 'not current user'

            for role in current_user.roles:
                for value in roles:
                    if role.get_name() == value:
                        return f(*args, **kwargs)

                    else:
                        for r in role.get_children():
                            if r.get_name() == value:
                                return f(*args, **kwargs)

            else:
                return 'Authorized Denied'

        return wrap

    return deco


def has_permissions(*permission):
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if not current_user:
                return 'not current user'

            for role in current_user.roles:
                for perm in role.get_permission():
                    for value in permission:
                        if perm == value:
                            return f(*args, **kwargs)
            else:
                return 'Permission Denied'

        return wrap

    return deco
