from sqlalchemy_serializer import SerializerMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(50), unique=True)
    _password_hash = db.Column(db.String(100), nullable=False)

    courses = db.relationship('Course', backref='user')
    orders = db.relationship('OrderRecord', backref='user')
    serialize_rules = ('-courses.user', '-orders.user',)

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Not allowed")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tracking_id = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(50), default='Unpaid')
    total_amount = db.Column(db.Float, nullable=False)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_details = db.Column(db.Text, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Completed')