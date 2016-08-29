# coding: utf-8
import time
from flask import Flask, request, jsonify, g
from flask_restful import Resource, Api
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.config['SECRET_KEY'] = 'LLCllc,./'
api = Api(app)

Base = declarative_base()
engine = create_engine("mysql+pymysql://root:@localhost:3306/llc", echo=True)
Session = sessionmaker(bind=engine)
session = Session()

auth = HTTPBasicAuth()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String, index=True)
    password_hash = Column(String)
    is_admin = Column(Integer)
    baby_id = Column(String)
    register_time = Column(DateTime)
    last_login_time = Column(DateTime)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = session.query(User).get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    print(username_or_token + ":" + password)
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = session.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    user.last_login_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    session.add(user)
    session.commit()
    return True


class Register(Resource):
    @staticmethod
    def post():
        username = request.json.get('username')
        password = request.json.get('password')
        if username is None or password is None:
            return jsonify({'status': False, "msg": "用户名或密码不能为空"})
        if session.query(User).filter_by(username=username).first() is not None:
            return jsonify({'status': False, "msg": "用户名已存在"})
        user = User(username=username)
        user.hash_password(password)
        user.register_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        session.add(user)
        session.commit()
        return jsonify({'status': True, 'msg': "注册成功"})


class Login(Resource):
    @staticmethod
    @auth.login_required
    def post():
        token = g.user.generate_auth_token(600)
        return jsonify({'status': True, 'msg': '登录成功', 'token': token.decode('ascii'), 'duration': 600})


class BindBabyId(Resource):
    @staticmethod
    @auth.login_required
    def post():
        baby_id = request.json.get('baby_id')
        user = session.query(User).filter_by(baby_id=baby_id).first()
        if user:
            return jsonify({'status': False, "msg": "此id已被绑定,请联系管理员添加"})
        user = g.user
        user.baby_id = baby_id
        user.is_admin = 1
        session.add(user)
        session.commit()
        return jsonify({'status': True, "msg": "绑定成功"})


class RequestBindBabyId(Resource):
    @staticmethod
    @auth.login_required
    def post():
        baby_id = request.json.get('baby_id')
        add_username = request.json.get('add_username')
        user = session.query(User).filter_by(username=add_username).first()
        if not user:
            return jsonify({'status': False, "msg": "用户不存在"})
        if g.user.is_admin is 0:
            return jsonify({'status': False, "msg": "不是管理员无法添加"})
        user.baby_id = baby_id
        user.is_admin = 0
        session.add(user)
        session.commit()
        return jsonify({'status': True, "msg": "添加成功"})


class GetInfo(Resource):
    @staticmethod
    @auth.login_required
    def post():
        return jsonify(
            {'status': True, "msg": "获取成功", 'data': {'baby_id': g.user.baby_id, 'is_admin': g.user.is_admin}})


class UploadLocation(Resource):
    @staticmethod
    @auth.login_required
    def post():
        lac = request.json.get('lac')
        lng = request.json.get('lng')


api.add_resource(Register, '/api/v1/register')
api.add_resource(Login, '/api/v1/login')
api.add_resource(BindBabyId, '/api/v1/bind')
api.add_resource(RequestBindBabyId, '/api/v1/request_bind')
api.add_resource(GetInfo, '/api/v1/get_info')

if __name__ == '__main__':
    app.run(debug=True)
