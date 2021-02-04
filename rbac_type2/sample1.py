from flask import Flask, Response
from flask_restx import Api, fields, Resource
from rbac_type2.rbac_build.model_example import UserMixin, RoleMixin
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

api = Api(app, version='1.0', title='Rbac', description='RBAC POC')

ns = api.namespace('rbac', description="role based access control")
data = api.model('rbac_info', {'user_id': fields.String('user_id')})


class Role(RoleMixin):
    def __repr__(self):
        return 'Role:{} Permission:{}'.format(self.name, self.perm)


class User(UserMixin):
    def __repr__(self):
        return '{}'.format(self.roles)


Manager = Role(name='Manager', perm=['Write'])
Employee = Role(name='Employee', perm=['Read', 'Write', 'Execute'])
Client = Role(name='Client', perm=['Read'])

vipin = User(roles=[Manager])
ajay = User(roles=[Employee])
harsh = User(roles=[Client])

user_dict = {'vipin': vipin, 'ajay': ajay, 'harsh': harsh}
current_user = vipin


def has_roles(*roles):
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
                return 'Authorization Denied'

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


@app.url_value_preprocessor
def br(endpoint, values):
    for id in user_dict.keys():
        if id == values['id']:
            global current_user
            current_user = user_dict[id]
            #print(endpoint)
            break
    else:
        raise Exception('User not registered')


@ns.route('/<string:id>')
class CreateUser(Resource):

    @has_roles('Manager', 'Employee')
    @has_permissions('Read')
    def get(self, id):
        return Response('College Portal: \n{}'.format(current_user))


if __name__ == '__main__':
    app.run(port=9988, debug=True)