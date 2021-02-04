from flask import Flask, Response
from flask_rbac import RBAC, RoleMixin, UserMixin

app = Flask(__name__)
app.config['RBAC_USE_WHITE'] = True

rbac = RBAC(app)


@rbac.as_role_model
class Role(RoleMixin):
    def __repr__(self):
        return '<Role %s>' % self.name


@rbac.as_user_model
class User(UserMixin):
    def __repr__(self):
        return '<User %s>' % self.roles


everyone = Role('everyone')
admin = Role('admin')
staff_role = Role('staff_role')
other_role = Role('other_role')
special = Role('special')

admin.add_parent(everyone)
staff_role.add_parents(everyone, admin)

anonymous = User(roles=[everyone])
normal_user = User(roles=[other_role])
staff_role_user = User(roles=[staff_role])
special_user = User(roles=[special])
admin_roles_user = User(roles=[admin, other_role, everyone])

current_user = anonymous

rbac.set_user_loader(lambda: current_user)


@app.route('/')
@rbac.allow(roles=['everyone'], methods=['GET'])
def index():
    return Response('index')


@app.route('/a')
@rbac.allow(roles=['special'], methods=['GET'])
def a():
    return Response('Hello')


@app.route('/b', methods=['GET', 'POST'])
@rbac.allow(roles=['admin'], methods=['GET'])
@rbac.allow(roles=['staff_role', 'special'], methods=['POST'])
def b():
    return Response('Hello from /b')


@app.route('/c')
@rbac.allow(roles=['everyone'], methods=['GET'])
@rbac.deny(roles=['admin'], methods=['GET'], with_children=False)
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
@rbac.deny(roles=['admin'], methods=['POST'])
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


if __name__ == '__main__':
    print(rbac.has_permission('GET', 'h'))
    app.run(port=8800, debug=True)
