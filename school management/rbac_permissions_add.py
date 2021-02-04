from flask import Flask, Response
from flask_rbac import RBAC, UserMixin, RoleMixin
from functools import wraps


class Role(RoleMixin):
    def __repr__(self):
        return 'Role: %s' % self.name


class User(UserMixin):
    def __init__(self, user_permission, roles):
        self.user_permission = user_permission
        super(User, self).__init__(roles)

    def __repr__(self):
        return 'user_permission:{} {}'.format(self.user_permission, self.roles)


P = Role('P')
Q = Role('Q')
R = Role('R')

A = User(user_permission=['read'], roles=[Q])
B = User(user_permission=['access'], roles=[P, Q])
C = User(user_permission=['write'], roles=[R])


user_dict = {'A': A, 'B': B, 'C': C}
current_user = A


def start_app(with_factory=False, use_white=True):
    global current_user
    app = Flask(__name__)

    if use_white:
        app.config['RBAC_USE_WHITE'] = True
    else:
        app.config['RBAC_USE_WHITE'] = False

    if with_factory:
        rbac = RBAC()
        rbac.init_app(app)
    else:
        rbac = RBAC(app)

    @app.route('/login/<string:name>', methods=['GET', 'POST'])
    @rbac.allow(['Q'], methods=['GET', 'POST'])
    def login(name):
        try:
            for i in user_dict.keys():
                if i == name:
                    global current_user
                    current_user = user_dict[i]
                    return 'signed-in'

            else:
                return 'Not defined'

        except Exception as ex:
            print(ex)

    rbac.set_user_loader(lambda: current_user)
    rbac.set_user_model(User)
    rbac.set_role_model(Role)

    def has_permissions(*permission):
        def deco(f):
            @wraps(f)
            def wrap(*args, **kwargs):
                if not current_user:
                    return 'not current user'

                print(permission)
                for i in current_user.user_permission:
                    for j in permission:
                        if i == j:
                            return f(*args, **kwargs)

                else:
                    return 'Not Authorized'

            return wrap
        return deco

    @app.route('/create')
    @rbac.allow(roles=['P', 'Q'], methods=['GET'])
    @has_permissions('read', 'access')
    def create_user():
        return Response('Teacher Portal: \n{}'.format(current_user))

    app.run(port=9988, debug=True)
    return app


if __name__ == '__main__':
    start_app()

