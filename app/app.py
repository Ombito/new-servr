from flask_cors import CORS
from flask import Flask, jsonify, request, session, make_response
from flask_restful import Api, Resource
from models import db, User, Order
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

# add models
db.init_app(app)
api = Api(app)
migrate = Migrate(app, db)
Session(app)

class Index(Resource):
    def get(self):
        response_body = '<h1>Welcome</h1>'
        status = 200
        headers = {}
        return make_response(response_body,status,headers)
    
    
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
    

class OrderResource(Resource):
    def get(self):
        all_orders = [order.to_dict() for  order in Order.query.all()]
        
        return make_response(jsonify(all_orders),200)

        
    def post(self):
        data = request.get_json()

        tracking_id = data.get('tracking_id')
        total_amount = data.get('total_amount')
        location = data.get('location')
        status = data.get('status')
        user_id=data.get('user_id')

        if tracking_id and total_amount and location:
            new_order = Order(tracking_id=tracking_id, total_amount=total_amount, location=location, status=status, user_id=user_id)

            db.session.add(new_order)
            db.session.commit()
      
            return make_response(jsonify(new_order.to_dict(), 201))
        
        return {"error": "Order details must be added"}, 422
    


class OrderRecordById(Resource):
    def get(self,id):
        pass
        order_record=Order.query.filter_by(id=id).first().to_dict()

        return make_response(jsonify(order_record),200)
    

    def patch(self, id):
        order = Order.query.filter_by(id=id).first()

        if order:
            for attr in request.get_json():
                setattr(order,attr,request.get_json()[attr])

                db.session.add(order)
                db.session.commit()
            return make_response(jsonify(order.to_dict(), 200)) 
        
        
        return {"error": "Order record not found"}, 404


    def delete(self, id):
        order = Order.query.filter_by(id=id).first()

        if order:
            db.session.delete(order)
            db.session.commit()
            return {"message": "Order record deleted successfully"}, 200
        else:
            return {"error": "Order record not found"}, 404
    



class Payment(Resource):
    def process_payment():
        data = request.get_json()
        order = Order.query.get(data['order_id'])
        
        if not order:
            return jsonify({"message": "Order not found"}), 404
        
        new_payment = Payment(
            order_id=order.id,
            payment_method=data['payment_method'],
            payment_details=data['payment_details']
        )
        db.session.add(new_payment)
        db.session.commit()

        order.payment_status = 'Paid'
        db.session.commit()

        return jsonify({"message": "Payment processed successfully"}), 200



api.add_resource(Index,'/', endpoint='landing')
api.add_resource(UserResource, '/users', endpoint='users')
api.add_resource(UsersByID, '/users/<int:id>')
api.add_resource(CheckSession,'/session_user',endpoint='session_user' )
api.add_resource(SignupUser, '/signup_user', endpoint='signup')
api.add_resource(LoginUser, '/login_user', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
# api.add_resource(TrackOrder, '/orders/<int:id>')
api.add_resource(OrderResource,'/orders', endpoint='order')
api.add_resource(OrderRecordById, '/orders/<int:id>', endpoint='ordersbyid')


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