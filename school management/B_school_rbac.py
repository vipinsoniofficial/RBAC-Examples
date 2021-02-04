from flask import Flask, Response
from flask_rbac import RBAC, UserMixin, RoleMixin


class Role(RoleMixin):
    def __repr__(self):
        return 'Role: %s' % self.name


class User(UserMixin):
    def __init__(self, name,age, company, roles):
        self.name = name
        self.company = company
        self.age = age
        super(User, self).__init__(roles)

    def __repr__(self):
        return 'Name:{}   age:{}   Company:{} {}'.format(self.name, self.age, self.company, self.roles)


start = Role('start')
teacher = Role('teacher')
student = Role('student')
accounts = Role('accounts')
hr = Role('hr')
maintenance = Role('maintenance')
dean = Role('dean')
IT = Role('IT')


#teacher.add_parent(student)
#hr.add_parents(accounts, maintenance)


vipin = User(name='Vipin', age=24, company='B School', roles=[student])
ronit = User(name='Rohit', age=35, company='B School', roles=[teacher])
start = User(name='Start point', age=0, company='B School', roles=[start])
ajay = User(name='Abhay', age=30, company='B School', roles=[maintenance])
ram = User(name='Ram', age=44, company='B School', roles=[accounts])
vk = User(name='VK', age=38, company='B School', roles=[hr])
nidhi = User(name='Nidhi', age=45, company='B School', roles=[dean])
saurav = User(name='Saurav', age=26, company='B School', roles=[IT])


user_dict = {'vipin': vipin, 'ronit': ronit, 'start': start, 'ajay': ajay, 'ram': ram, 'vk': vk,
             'nidhi': nidhi, 'saurav': saurav}
current_user = start


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
    @rbac.allow(['start'], methods=['GET', 'POST'])
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

    @app.route('/teacher')
    @rbac.allow(roles=['teacher'], methods=['GET','POST'])
    def teachers_portal():
        return Response('Teacher Portal: \n{}'.format(current_user))

    @app.route('/student')
    @rbac.allow(roles=['student'], methods=['GET', 'POST'])
    def student_portal():
        return Response('Student Portal:\n{}'.format(current_user.name))

    @app.route('/accounts', methods=['GET', 'POST'])
    @rbac.allow(roles=['accounts'], methods=['GET'])
    def accounts_portal():
        return Response('Accounts Department Portal:\n{}'.format(current_user.name))

    @app.route('/acc', methods=['GET', 'POST'])
    @rbac.allow(roles=['accounts'], methods=['GET'], with_children=False)
    @rbac.deny(roles=['hr'], methods=['POST'])
    def accounts_user_portal():
        return Response('Accounts Department Personal Portal:\n{}'.format(current_user.name))

    @app.route('/hr')
    @rbac.allow(roles=['hr'], methods=['GET', 'PUT'])
    @rbac.deny(roles=['teacher', 'student'], methods=['GET'], with_children=False)
    def hr_portal():
        return Response('HR Portal:\n{}'.format(current_user.name))

    @app.route('/maintain')
    @rbac.allow(roles=['maintenance'], methods=['GET', 'PUT', 'POST'])
    def maintenance_portal():
        return Response('Maintenance Portal:\n{}'.format(current_user.name))

    @app.route('/dean', methods=['POST'])
    @rbac.allow(roles=['dean'], methods=['GET', 'POST', 'PUT', 'DELETE'])
    @rbac.deny(roles=['teacher', 'accounts', 'hr'], methods=['POST', 'DELETE', 'PUT'])
    def dean_portal():
        return Response('Dean Portal:\n{}'.format(current_user.name))

    @app.route('/common', methods=['GET'])
    @rbac.exempt
    def commom_portal():
        return Response('Common Portal:\n{}'.format(current_user.name))

    @app.route('/IT', methods=['GET'])
    @rbac.allow(['IT', 'dean'], methods=['GET', 'ACCESS_H'], with_children=False)
    def it_portal():
        print(rbac.has_permission('ACCESS_H', 'it_portal'))
        return Response('IT Portal:\n{}'.format(current_user.name))

    @app.route('/exam', methods=['GET'])
    @rbac.allow(['teacher'], methods=['ACCESS_H'], with_children=False)
    def exam():
        return Response('EXAM Portal:\n{}'.format(current_user.name))

    app.run(port=9999, debug=True)
    return app


if __name__ == '__main__':
    start_app()
