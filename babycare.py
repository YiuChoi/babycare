# coding: utf-8
from flask import Flask, request, jsonify, g
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KET'] = 'llcLLC,./'
auth = HTTPBasicAuth()

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

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KET'], expires_in == expiration)
        return s.dump({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    print(username_or_token+':'+password)
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = session.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/register', methods=['POST'])
def register():
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


@app.route('/login', methods=['POST'])
@auth.login_required
def login():
    token = g.user.generate_auth_token()
    return jsonify({'status': True, 'msg': '登录成功', 'data': {'token': token.decode('ascii'), 'duration': 600}})


if __name__ == '__main__':
    app.run(debug=True)
