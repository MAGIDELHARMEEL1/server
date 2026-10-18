import express from 'express';
import cors from 'cors';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';
import { Server } from 'socket.io';
import http from 'http';
import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "xxxxnx-secret-key-change-me";

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const db = new sqlite3.Database('./database.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE, password TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT, description TEXT, category TEXT,
    filename TEXT, thumbnail TEXT, user_id INTEGER,
    views INTEGER DEFAULT 0, is_sensitive INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS lives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT, category TEXT, host_id INTEGER, host_name TEXT,
    is_live INTEGER DEFAULT 1, viewers INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 500*1024*1024 } });

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "غير مسجل" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "توكن غير صالح" }); }
}

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "بيانات ناقصة" });
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name, email, password) VALUES (?,?,?)', [name, email, hashed], function(err) {
    if (err) return res.status(400).json({ error: "الإيميل موجود بالفعل" });
    const token = jwt.sign({ id: this.lastID, name, email }, JWT_SECRET);
    res.json({ token, user: { id: this.lastID, name, email } });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email=?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: "مستخدم غير موجود" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "باسورد خطأ" });
    const token = jwt.sign({ id: user.id, name: user.name, email }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email } });
  });
});

app.get('/api/videos', (req, res) => {
  db.all('SELECT videos.*, users.name as host_name FROM videos LEFT JOIN users ON videos.user_id=users.id ORDER BY created_at DESC', (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/upload', auth, upload.fields([{ name: 'video' }, { name: 'thumbnail' }]), (req, res) => {
  const { title, description, category } = req.body;
  const videoFile = req.files['video']?.[0]?.filename;
  const thumbFile = req.files['thumbnail']?.[0]?.filename;
  if (!videoFile) return res.status(400).json({ error: "فيديو مطلوب" });
  db.run('INSERT INTO videos (title, description, category, filename, thumbnail, user_id, is_sensitive) VALUES (?,?,?,?,?,?,1)',
    [title, description, category, videoFile, thumbFile, req.user.id], function(err) {
      res.json({ id: this.lastID, message: "تم الرفع بنجاح - سيظهر بعد المراجعة" });
    });
});

app.get('/api/lives', (req, res) => {
  db.all('SELECT * FROM lives WHERE is_live=1 ORDER BY viewers DESC', (err, rows) => res.json(rows));
});

app.post('/api/live/start', auth, (req, res) => {
  const { title, category } = req.body;
  db.run('INSERT INTO lives (title, category, host_id, host_name) VALUES (?,?,?,?)',
    [title, category, req.user.id, req.user.name], function(err) {
      res.json({ id: this.lastID, message: "بدأ البث" });
      io.emit('new_live', { id: this.lastID, title, host_name: req.user.name });
    });
});

app.post('/api/live/end/:id', auth, (req, res) => {
  db.run('UPDATE lives SET is_live=0 WHERE id=? AND host_id=?', [req.params.id, req.user.id], () => {
    res.json({ message: "انتهى البث" });
    io.emit('end_live', req.params.id);
  });
});

io.on('connection', (socket) => {
  socket.on('join_live', (liveId) => socket.join('live_'+liveId));
  socket.on('chat_message', (data) => {
    io.to('live_'+data.liveId).emit('new_message', data);
    io.emit('general_message', data);
  });
});

server.listen(PORT, () => console.log(`✅ الخادم شغال على http://localhost:${PORT}`));
