from flask import Flask, Response
from flask_restx import Api, fields, Resource

from rbac_check.rbac_build.__init__ import has_permissions, has_roles, get_current_user
from rbac_check.rbac_build.model import UserMixin, RoleMixin, PermissionMixin

app = Flask(__name__)

api = Api(app, version='1.0', title='Rbac', description='RBAC POC')

ns = api.namespace('rbac', description="role based access control")
data = api.model('rbac_info', {'user_id': fields.String('user_id')})


class Permission(PermissionMixin):
    def __repr__(self):
        return 'Permission: {}'.format(self.perm)


class Role(RoleMixin):
    def __repr__(self):
        return 'Role:{} {}'.format(self.name, self.permissions)


class User(UserMixin):
    def __repr__(self):
        return '{}'.format(self.roles)


Read = Permission(perm='Read')
Write = Permission(perm='Write')
Execute = Permission(perm='Execute')

Manager = Role(name='Manager', permissions=[Read])
Employee = Role(name='Employee', permissions=[Write])
Client = Role(name='Client', permissions=[Execute])

Employee.add_parent(Manager)
Client.add_parent(Manager)

vipin = User(roles=[Manager])
ajay = User(roles=[Employee])
harsh = User(roles=[Client])

user_dict = {'vipin': vipin, 'ajay': ajay, 'harsh': harsh}
current_user = ''


@app.url_value_preprocessor
def br(endpoint, values):
    for id in user_dict.keys():
        if id == values['id']:
            global current_user
            current_user = user_dict[id]
            get_current_user(current_user)
            print(endpoint)
            break
    else:
        raise Exception('User not registered')


@ns.route('/<string:id>')
class CreateUser(Resource):

    @has_roles('Employee', 'Manager')
    @has_permissions('Write')
    def get(self, id):
        return Response('College Portal: \n{}'.format(current_user))

    @has_roles('Employee')
    @has_permissions('Execute')
    def post(self, id):
        return Response('College Portal: \n{}'.format(current_user))


if __name__ == '__main__':
    app.run(port=9999, debug=True)

"""
Scenario:
Employee.add_parent(Manager)
Client.add_parent(Manager)
Manager is parent of Employee, Client which means roles and permissions are also accessible to manager

In post() method: roles doesnt have client but permission has execute so if we enter Manger(vipin -> defined)
                  in input. Access will be granted to manager

"""