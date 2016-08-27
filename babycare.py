from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
from flask_oauthlib.provider import OAuth2Provider

app = Flask(__name__)
api = Api(app)
oauth = OAuth2Provider(app)

parser = reqparse.RequestParser()
parser.add_argument('task')


# TodoList
# shows a list of all todos, and lets you POST to add new tasks
class User(Resource):
    def get(self):
        abort(404, message="Not Allow GET Request")

    def post(self):
        args = parser.parse_args()
        todo_id = int(max(TODOS.keys()).lstrip('todo')) + 1
        todo_id = 'todo%i' % todo_id
        TODOS[todo_id] = {'task': args['task']}
        return TODOS[todo_id], 201


api.add_resource(User, '/users')

if __name__ == '__main__':
    app.run(debug=True)
