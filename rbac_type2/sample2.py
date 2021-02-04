from flask import Flask, Response
from flask_restx import Api, fields, Resource

from rbac_type2.rbac_build.__init__ import has_permissions, has_roles, get_current_user
from rbac_type2.rbac_build.model_example import UserMixin, RoleMixin

app = Flask(__name__)

api = Api(app, version='1.0', title='Rbac', description='RBAC POC')

ns = api.namespace('rbac', description="role based access control")
data = api.model('rbac_info', {'user_id': fields.String('user_id')})


class Role(RoleMixin):
    def __repr__(self):
        return 'Role:{} Permission:{}'.format(self.name, self.perm)


class User(UserMixin):
    def __repr__(self):
        return '{}'.format(self.roles)


Manager = Role(name='Manager', perm=['Read', 'Write'])
Employee = Role(name='Employee', perm=['Read'])
Client = Role(name='Client', perm=['Read'])

#Employee.add_parent(Manager)

vipin = User(roles=[Manager])
ajay = User(roles=[Employee])
harsh = User(roles=[Client])

user_dict = {'vipin': vipin, 'ajay': ajay, 'harsh': harsh}
current_user = vipin


@app.url_value_preprocessor
def br(endpoint, values):
    for id in user_dict.keys():
        if id == values['id']:
            global current_user
            current_user = user_dict[id]
            get_current_user(current_user)
            # print(endpoint)
            break
    else:
        raise Exception('User not registered')


@ns.route('/<string:id>')
class CreateUser(Resource):

    @has_roles('Employee')
    @has_permissions('Read')
    def get(self, id):
        return Response('College Portal: \n{}'.format(current_user))


if __name__ == '__main__':
    app.run(port=9999, debug=True)
