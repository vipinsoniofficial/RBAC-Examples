from flask import Flask, Response
from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __repr__(self):
        return 'Role: %s' % self.name


class User(UserMixin):
    def __init__(self, name, company, roles):
        self.name = name
        self.company = company
        super(User, self).__init__(roles)

    def __repr__(self):
        return 'Name:{} Company:{} {}'.format(self.name,self.company, self.roles)


everyone = Role('everyone')
admin = Role('admin')
staff_role = Role('staff_role')
other_role = Role('other_role')
special = Role('special')
start = Role('start')

admin.add_parent(everyone)
staff_role.add_parents(everyone)


vipin = User(name='Vipin', company='psi', roles=[everyone])
ronit = User(name='Rohit', company='psi', roles=[other_role])
start = User(name='Nn', company='psi', roles=[start])
nakul = User(name='Nakul', company='psi', roles=[admin, staff_role, start])
ram = User(name='Ram', company='psi', roles=[special])
vk = User(name='VK', company='psi', roles=[staff_role])


user_dict = {'vipin': vipin, 'ronit': ronit, 'start': start, 'nakul': nakul, 'ram': ram, 'vk': vk}
current_user = start


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

    @app.route('/signin/<string:name>', methods=['GET', 'POST'])
    @rbac.allow(['start'], methods=['GET', 'POST'])
    def signin(name):
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

    @app.route('/')
    @rbac.allow(roles=['everyone'], methods=['GET'])
    def index():
        return Response('index {}'.format(current_user.name))

    @app.route('/a')
    @rbac.allow(roles=['special'], methods=['GET'])
    def a():
        return Response('Hello from {} in /a'.format(current_user.name))

    @app.route('/b', methods=['GET', 'POST'])
    @rbac.allow(roles=['admin'], methods=['GET'])
    @rbac.allow(roles=['staff_role', 'special'], methods=['POST'])
    def b():
        return Response('Hello from {} in /b'.format(current_user.name))

    @app.route('/c')
    @rbac.allow(roles=['everyone'], methods=['GET'])
    @rbac.deny(roles=['admin'], methods=['GET'], with_children=False)
    @rbac.allow(roles=['staff_role'], methods=['GET'])
    def c():
        return Response('Hello from {} in /c'.format(current_user.name))

    @app.route('/d')
    @rbac.deny(roles=['everyone'], methods=['GET'])
    def d():
        return Response('Hello from {} in /d'.format(current_user.name))

    @app.route('/e')
    @rbac.deny(roles=['everyone'], methods=['GET'], with_children=True)
    def e():
        return Response('Hello from {} in /e'.format(current_user.name))

    @app.route('/f', methods=['POST'])
    @rbac.deny(roles=['admin'], methods=['POST'])
    def f():
        return Response('Hello from {} in /f'.format(current_user.name))

    @app.route('/g', methods=['GET'])
    @rbac.exempt
    def g():
        return Response('Hello from {} in /g'.format(current_user.name))

    @app.route('/h', methods=['GET'])
    @rbac.allow(['everyone'], methods=['GET'], with_children=False)
    def h():
        return Response('Hello from {} in /h'.format(current_user.name))

    app.run(port=9999, debug=True)
    return app


if __name__ == '__main__':
    createapp()
