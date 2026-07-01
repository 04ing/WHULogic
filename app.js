const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

// 配置静态资源服务
app.use(express.static('.'));

// 创建数据库连接
const db = new sqlite3.Database('./users.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
});

app.use(express.json());
app.use(cors());

// 注册接口
app.post('/api/register', async (req, res) => {
  console.log('收到注册请求:', req.body);
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    db.run('INSERT INTO users (username, password) VALUES (?, ?)',
      [req.body.username, hashedPassword],
      function(err) {
        if (err) {
          return res.status(400).json({ error: '用户名已存在' });
        }
        res.status(201).json({ message: '注册成功' });
      });
  } catch {
    res.status(500).send();
  }
});

// 登录接口
app.post('/api/login', (req, res) => {
  console.log('收到登录请求:', req.body);
  // 添加在cors中间件之后
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: '服务器内部错误' });
  });
  
  // 修改登录接口的错误处理
  db.get('SELECT * FROM users WHERE username = ?', [req.body.username], 
    async (err, user) => {
      if (err) {
        console.error('数据库查询错误:', err);
        return res.status(500).json({ error: '服务器错误' });
      }
      if (!user || !await bcrypt.compare(req.body.password, user.password)) {
        return res.status(401).json({ error: '用户名或密码错误' });
      }
      
      const accessToken = jwt.sign({ username: user.username }, 'your_secret_key');
      res.json({ accessToken });
  });
});

// 新增密码重置路由
const nodemailer = require('nodemailer');

// 配置邮件传输器
const transporter = nodemailer.createTransport({
  service: 'QQ',
  auth: {
    user: 'your_email@qq.com',
    pass: 'your_email_password'
  }
});

// 生成随机验证码
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 重置密码请求
app.post('/api/reset-password', (req, res) => {
  const { username } = req.body;
  const verificationCode = generateVerificationCode();

  db.run('UPDATE users SET resetToken = ?, resetTokenExpires = ? WHERE username = ?',
    [verificationCode, Date.now() + 3600000, username],
    function(err) {
      if (err) return res.status(500).json({ error: '数据库错误' });

      const mailOptions = {
        from: 'your_email@qq.com',
        to: username,
        subject: '密码重置验证码',
        text: `您的验证码是：${verificationCode}，有效期1小时`
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) return res.status(500).json({ error: '邮件发送失败' });
        res.json({ message: '验证码已发送至注册邮箱' });
      });
  });
});

// 更新密码
app.post('/api/update-password', async (req, res) => {
  const { username, code, newPassword } = req.body;

  db.get('SELECT * FROM users WHERE username = ? AND resetToken = ? AND resetTokenExpires > ?',
    [username, code, Date.now()],
    async (err, user) => {
      if (err) return res.status(500).json({ error: '数据库错误' });
      if (!user) return res.status(400).json({ error: '验证码无效或已过期' });

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      db.run('UPDATE users SET password = ?, resetToken = NULL, resetTokenExpires = NULL WHERE username = ?',
        [hashedPassword, username],
        function(err) {
          if (err) return res.status(500).json({ error: '密码更新失败' });
          res.json({ message: '密码重置成功' });
      });
  });
});

const PORT = 3000;
// 在服务器启动监听处添加错误处理
app.listen(PORT, (err) => {
  if (err) {
    console.error('服务器启动失败:', err);
    return;
  }
  console.log(`Server running on port ${PORT}`);
});