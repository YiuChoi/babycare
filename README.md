### 注册
```
curl -H "Content-Type: application/json" -X POST -d '{"username":"xyz","password":"xyz"}' http://localhost:5000/api/v1/register

```

### 登录
```
  curl -u xyz:xyz http://127.0.0.1:5000/api/v1/login -X POST
  {
  "duration": 600,
  "msg": "\u767b\u5f55\u6210\u529f",
  "status": true,
  "token": "eyJpYXQiOjE0NzI0NTkwNDIsImV4cCI6MTQ3MjQ1OTY0MiwiYWxnIjoiSFMyNTYifQ.eyJpZCI6MX0.LLE5eVOsARkosrSyXeusMOtpL4z2OnKU_hcpSGgIGmw"
 }
```

### 认证
```
 curl -u eyJhbGciOiJIUzI1NiIsImV4cCI6MTM4NTY2OTY1NSwiaWF0IjoxMzg1NjY5MDU1fQ.eyJpZCI6MX0.XbOEFJkhjHJ5uRINh2JA1BPzXjSohKYDRT472wGOvjc:unused -i -X GET http://127.0.0.1:5000/api/resource
```


