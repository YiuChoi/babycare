# coding: utf-8
from flask import Flask, request, jsonify, g
from flask_restful import Resource, Api
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
api = Api(app)

Base = declarative_base()
engine = create_engine("mysql+pymysql://root:@localhost:3306/llc", echo=True)
Session = sessionmaker(bind=engine)
session = Session()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


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
        session.add(user)
        session.commit()
        return jsonify({'status': True, 'msg': "注册成功"})


class Login(Resource):
    @staticmethod
    def post():
        username = request.json.get('username')
        password = request.json.get('password')
        if username is None or password is None:
            return jsonify({'status': False, "msg": "用户名或密码不能为空"})
        user = session.query(User).filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return jsonify({'status': False, "msg": "用户名或密码不正确"})
        g.user = user
        return jsonify({'status': True, 'msg': '登录成功'})


api.add_resource(Register, '/api/v1/register')
api.add_resource(Login, '/api/v1/login')

if __name__ == '__main__':
    app.run(debug=True)
