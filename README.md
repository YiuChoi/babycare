
## API

### 注册
```
curl -H "Content-Type: application/json" -X POST -d '{"username":"xyz","password":"xyz"}' http://localhost:5000/api/v1/register

```

### 登录
```
  curl  -H "Content-Type: application/json" http://127.0.0.1:5000/auth -X POST  -d '{"username":"xyz","password":"xyz"}'
  {
  "token": "eyJpYXQiOjE0NzI0NTkwNDIsImV4cCI6MTQ3MjQ1OTY0MiwiYWxnIjoiSFMyNTYifQ.eyJpZCI6MX0.LLE5eVOsARkosrSyXeusMOtpL4z2OnKU_hcpSGgIGmw"
 }
 
 request.setHeader("Authorization", "JWT "+Base64.encodeBytes("login:password".getBytes()));
```

### 认证
```
 curl -H "Content-Type: application/json" -H "Authorization:JWT eyJpYXQiOjE0NzI0NTkwNDIsImV4cCI6MTQ3MjQ1OTY0MiwiYWxnIjoiSFMyNTYifQ.eyJpZCI6MX0.LLE5eVOsARkosrSyXeusMOtpL4z2OnKU_hcpSGgIGmw" -X POST http://127.0.0.1:5000/api/v1/get_info
 
  request.setHeader("Authorization", "JWT "+Base64.encodeBytes("login:password".getBytes()));
```


