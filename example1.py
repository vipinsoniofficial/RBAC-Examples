from flask import Flask, Response
from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __repr__(self):
        return '<Role %s>' % self.name


class User(UserMixin):
    def __repr__(self):
        return '<User %s>' % self.roles


everyone = Role('everyone')
logged_role = Role('logged_role')
staff_role = Role('staff_role')
other_role = Role('other_role')
special = Role('special')

logged_role.add_parent(everyone)
staff_role.add_parents(everyone, logged_role)

anonymous = User(roles=[everyone])
normal_user = User(roles=[logged_role])
staff_role_user = User(roles=[staff_role])
special_user = User(roles=[special])
many_roles_user = User(roles=[logged_role, other_role, everyone])

current_user = normal_user


def createapp(with_factory=False, use_white=True):
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

    rbac.set_user_loader(lambda: current_user)
    rbac.set_user_model(User)
    rbac.set_role_model(Role)

    @app.route('/')
    @rbac.allow(roles=['everyone'], methods=['GET'])
    def index():
        return Response('index')

    @app.route('/a')
    @rbac.allow(roles=['special'], methods=['GET'])
    def a():
        return Response('Hello')

    @app.route('/b', methods=['GET', 'POST'])
    @rbac.allow(roles=['logged_role'], methods=['GET'])
    @rbac.allow(roles=['staff_role', 'special'], methods=['POST'])
    def b():
        return Response('Hello from /b')

    @app.route('/c')
    @rbac.allow(roles=['everyone'], methods=['GET'])
    @rbac.deny(roles=['logged_role'], methods=['GET'], with_children=False)
    @rbac.allow(roles=['staff_role'], methods=['GET'])
    def c():
        return Response('Hello from /c')

    @app.route('/d')
    @rbac.deny(roles=['everyone'], methods=['GET'])
    def d():
        return Response('Hello from /d')

    @app.route('/e')
    @rbac.deny(roles=['everyone'], methods=['GET'], with_children=True)
    def e():
        return Response('Hello from /e')

    @app.route('/f', methods=['POST'])
    @rbac.deny(roles=['logged_role'], methods=['POST'])
    def f():
        return Response('Hello from /f')

    @app.route('/g', methods=['GET'])
    @rbac.exempt
    def g():
        return Response('Hello from /g')

    @app.route('/h', methods=['GET'])
    @rbac.allow(['anonymous'], methods=['GET'], with_children=False)
    def h():
        return Response('Hello from /h')

    app.run(port=9999, debug=True)
    return app


if __name__ == '__main__':
    createapp()
