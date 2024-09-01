from flask_cors import CORS
from flask import Flask, jsonify, request, session, make_response
from flask_restful import Api, Resource
from models import db, User
from flask_migrate import Migrate
from werkzeug.exceptions import NotFound
import os
from sqlalchemy import and_, func
from datetime import datetime, timedelta
from flask_session import Session
import secrets
import jwt
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, support_credentials=True, allow_headers=["Content-Type", "Authorization"])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_FILE_DIR'] = 'session_dir'
app.config['JSONIFY_PRETTYPRINT_REGULAR']= True


db.init_app(app)
api = Api(app)
migrate = Migrate(app, db)
Session(app)

class Index(Resource):
    def get(self):
        response_body = '<h1>Hello World</h1>'
        status = 200
        headers = {}
        return make_response(response_body,status,headers)
    
    # login route
class LoginUser(Resource):
    def post(self):
        email  = request.get_json().get('email')
        password = request.get_json().get("password")

        user = User.query.filter(User.email == email).first()

        if user:
            if user.authenticate(password):
                token = jwt.encode({'user_id': user.id}, app.config['SECRET_KEY'], algorithm='HS256')
                return {'token': token}, 200
                
            else:
                return make_response(jsonify({"error": "Username or password is incorrect"}), 401)
        else:
            return make_response(jsonify({"error": "User not Registered"}), 404)

        
     # signup resource
class SignupUser(Resource):
    def post(self):
        try:
            data = request.get_json()

            full_name = data.get('full_name')
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            if full_name and username and email and password:
                new_user = User(full_name=full_name, username=username, email=email)
                new_user.password_hash = password
                db.session.add(new_user)
                db.session.commit()

                session['user_id']=new_user.id
                session['user_type'] = 'user'

                return make_response(jsonify(new_user.to_dict()),201)
            
            return make_response(jsonify({"error": "user details must be added"}),422)
    
        except Exception as e:
            return make_response(jsonify({"error": str(e)}), 500)


    #logout resource
class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id']=None
            return {"message": "User logged out successfully"}
        else:
            return {"error":"User must be logged in to logout"}

class CheckSession(Resource):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Authorization header missing'}, 401

        try:
            token = auth_header.split()[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')
            if user_id:
                user = User.query.get(user_id)
                if user:
                    return user.to_dict(), 200
                else:
                    return {'error': 'User not found'}, 404
            else:
                return {'error': 'Invalid token'}, 401
        except jwt.ExpiredSignatureError:
            return {'error': 'Token has expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401

    

    #  all users route
class UserResource(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]

        return make_response(jsonify(users),200) 

class UsersByID(Resource):
    def get(self, id): 
        
        response_dict = User.query.filter_by(id=id).first().to_dict()

        response = make_response(
            jsonify(response_dict),
            200,
        )

        return response
    


api.add_resource(Index,'/', endpoint='landing')

    # user resources
api.add_resource(UserResource, '/users', endpoint='users')
api.add_resource(UsersByID, '/users/<int:id>')
api.add_resource(CheckSession,'/session_user',endpoint='session_user' )
api.add_resource(SignupUser, '/signup_user', endpoint='signup')
api.add_resource(LoginUser, '/login_user', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


@app.before_request
def before_request():
    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Credentials': 'true',
            'Content-Type': 'application/json'
        }
        return make_response('', 200, headers)
    
    
@app.errorhandler(NotFound)
def handle_not_found(e):
    response = make_response(
        "Not Found:The requested endpoint(resource) does not exist",
        404
        )
    return response


if __name__ == '__main__':
    app.run(port=5555, debug=True)