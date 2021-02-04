from flask import Flask, Response, g, current_app
from flask_restx import Api, fields, Resource
from flask_rbac import RBAC, UserMixin, RoleMixin
from functools import wraps

app = Flask(__name__)
app.config['RBAC_USE_WHITE'] = True

rbac = RBAC(app)
api = Api(app, version='1.0', title='Rbac', description='RBAC POC', security=rbac.allow(roles=['Q', 'P'], methods=['PUT']))

ns = api.namespace('rbac', description="role based access control")
data = api.model('rbac_info', {'user_id': fields.String('user_id')})


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


P = Role(name='P', user_permission=['read'])
Q = Role(name='Q', user_permission=['access'])
R = Role(name='R', user_permission=['write'])

A = User(roles=[Q])
B = User(roles=[P, Q])
C = User(roles=[R])

user_dict = {'A': A, 'B': B, 'C': C}
current_user = B


def has_permissions(*permission):
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if not current_user:
                return 'not current user'

            for role in current_user.roles:
                for roles_permission in role.get_permission():
                    for value in permission:
                        if value == roles_permission:
                            return f(*args, **kwargs)

            else:
                return 'Not Authorized'

        return wrap

    return deco


@app.url_value_preprocessor
def br(endpoint, values):
    for id in user_dict.keys():
        if id == values['id']:
            global current_user
            current_user = user_dict[id]
            print(current_user)
            print('endpoint:', endpoint)
            break
    else:
        raise Exception('User not registered')


rbac.set_user_loader(lambda: current_user)
print('loader:', current_user)
rbac.set_user_model(User)
rbac.set_role_model(Role)


@ns.route('/<string:id>')
@rbac.allow(roles=['P', 'Q'], methods=['GET'])
class CreateUser(Resource):
    print('in class')

    @rbac.allow(roles=['Q', 'P'], methods=['GET'])
    @has_permissions('read')
    def get(self, id):
        print(self)
        print('id:', id)
        return Response('College Portal: \n{}'.format(current_user))

    print('after get')


if __name__ == '__main__':
    print('rbac permissions check', rbac.has_permission('GET', 'rbac_create_user'))
    #app.run(port=9999, debug=True)