from functools import wraps

from flask import Flask, Response
from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __init__(self, name, user_permission):
        self.user_permission = user_permission
        super(Role, self).__init__(name)

    def __repr__(self):
        return 'Role: {} Permission: {}'.format(self.name, self.user_permission)

    def get_permission(self):
        return self.user_permission


class User(UserMixin):
    def __repr__(self):
        return '{}'.format(self.roles)


Admin = Role(name='Admin', user_permission=['read', 'write', 'execute'])
Employee = Role(name='Employee', user_permission=['read'])
Manager = Role(name='Manager', user_permission=['write'])
Hr = Role(name='Hr', user_permission=['read', 'write'])

vipin = User(roles=[Employee])
rahul = User(roles=[Manager, Employee])
vinay = User(roles=[Admin])
shankar = User(roles=[Hr])

user_dict = {'vipin': vipin, 'rahul': rahul, 'vinay': vinay, 'shankar': shankar}
current_user = ''


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

    def has_permissions(*permission):
        def deco(f):
            @wraps(f)
            def wrap(*args, **kwargs):
                if not current_user:
                    return 'not current user'

                for role in current_user.roles:
                    for roles_perms in role.get_permission():
                        for value in permission:
                            if value == roles_perms:
                                return f(*args, **kwargs)

                else:
                    return 'Not Authorized'

            return wrap

        return deco

    @app.url_value_preprocessor
    def br(endpoint, values):
        for id in user_dict.keys():
            if id == values['user_id']:
                global current_user
                current_user = user_dict[id]
                break
        else:
            raise Exception('User not registered')

    rbac.set_user_loader(lambda: current_user)
    rbac.set_user_model(User)
    rbac.set_role_model(Role)

    @app.route('/create/<string:user_id>')
    @rbac.allow(roles=['Employee', 'Manager'], methods=['GET'])
    @has_permissions('read', 'write')
    def create_user(user_id):
        return Response('Company Portal: \nUserName:{} {}'.format(user_id, current_user))

    app.run(port=9888, debug=True)
    return app


if __name__ == '__main__':
    start_app()
