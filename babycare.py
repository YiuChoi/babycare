# coding: utf-8
import time
from flask import Flask, request, jsonify, g
from flask_httpauth import HTTPBasicAuth
from flask_restful import Resource, Api
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.config['SECRET_KEY'] = 'LLCllc,./'
api = Api(app)

Base = declarative_base()
engine = create_engine("mysql+pymysql://root:@localhost:3306/llc")
Session = sessionmaker(bind=engine)
session = Session()

auth = HTTPBasicAuth()


class Baby(Base):
    __tablename__ = "babys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    baby_uuid = Column(String(255), nullable=False, unique=True,primary_key=True)
    lac = Column(Float)
    lng = Column(Float)
    address = Column(String(255))
    last_time = Column(DateTime)


class UserBaby(Base):
    __tablename__ = "user_babys"

    id = Column(Integer, autoincrement=True, primary_key=True)
    is_admin = Column(Integer)
    username = Column(String(255), nullable=False)
    baby_uuid = Column(String(255), nullable=False)
    relationship = Column(String(255), nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False,primary_key=True)
    password_hash = Column(String(255), nullable=False)
    nickname = Column(String(255))
    register_time = Column(DateTime)
    last_login_time = Column(DateTime)

    def __repr__(self):
        return "<User(name='%s', nickname='%s', password='%s')>" % (self.name, self.nickname, self.password_hash)

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

Base.metadata.create_all(engine)


@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
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
        nickname = request.json.get('nickname')
        if username is None or password is None:
            return jsonify({'status': False, "msg": "用户名或密码不能为空"})
        if session.query(User).filter_by(username=username).first() is not None:
            return jsonify({'status': False, "msg": "用户名已存在"})
        user = User(username=username)
        user.hash_password(password)
        user.nickname = nickname
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
        baby_uuid = request.json.get('baby_uuid')
        userbaby = session.query(UserBaby).filter_by(baby_uuid=baby_uuid).first()
        if userbaby.is_admin:
            return jsonify({'status': False, "msg": "此id已被绑定,请联系管理员添加"})
        userbaby = g.user
        userbaby.baby_uuid = baby_uuid
        userbaby.is_admin = 1
        session.add(userbaby)
        session.commit()
        return jsonify({'status': True, "msg": "绑定成功"})


class AddBindBabyId(Resource):
    @staticmethod
    @auth.login_required
    def post():
        baby_uuid = request.json.get('baby_uuid')
        add_username = request.json.get('add_username')
        user_relation = request.json.get('user_relation')
        user = session.query(User).filter_by(username=add_username).first()
        userbaby = session.query(UserBaby).filter_by(username=add_username).first()
        if not user:
            return jsonify({'status': False, "msg": "用户不存在"})
        if userbaby.is_admin is 0:
            return jsonify({'status': False, "msg": "不是管理员无法添加"})
        userbaby.baby_uuid = baby_uuid
        userbaby.username = user.username
        userbaby.user_relation = user_relation
        userbaby.is_admin = 0
        session.add(userbaby)
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
        address = request.json.get('address')
        baby_uuid = request.json('baby_uuid')
        baby = session.query(Baby).filter_by(baby_uuid=baby_uuid).first()
        user = session.query(UserBaby).filter_by(username=g.user.username).first()
        if user.baby_uuid is not baby.baby_uuid:
            return jsonify({'status': False, "msg": "绑定后才能上传哦"})
        if not baby:
            baby = Baby()
        baby.address = address
        baby.lac = lac
        baby.lng = lng
        baby.baby_uuid = baby_uuid
        baby.last_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        session.add(baby)
        session.commit()
        return jsonify({'status': True, "msg": "s上传成功"})


class GetLocation(Resource):
    @staticmethod
    @auth.login_required
    def post():
        baby_uuid = request.json('baby_uuid')
        baby = session.query(Baby).filter_by(baby_uuid=baby_uuid).first()
        userbaby = session.query(UserBaby).filter_by(username=g.user.username).first()
        if userbaby.baby_uuid is not baby.baby_uuid:
            return jsonify({'status': False, "msg": "绑定后才能读取位置哦"})
        return jsonify({'status': True, "msg": "获取成功",
                        'data': {'lac': baby.lac, 'lng': baby.lng, 'address': baby.address,
                                 'last_time': baby.last_time}})


api.add_resource(Register, '/api/v1/register')
api.add_resource(Login, '/api/v1/login')
api.add_resource(BindBabyId, '/api/v1/bind')
api.add_resource(AddBindBabyId, '/api/v1/add_bind')
api.add_resource(GetInfo, '/api/v1/get_info')
api.add_resource(UploadLocation, '/api/v1/upload_location')
api.add_resource(GetLocation, '/api/v1/get_location')

if __name__ == '__main__':
    app.run(debug=True)
