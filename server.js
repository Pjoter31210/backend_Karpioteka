import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import bodyParser from 'body-parser';
import { promises as fs } from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';  // Dodajemy Mongoose
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB URI (dodaj w .env)
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Połączono z MongoDB'))
  .catch((error) => console.error('Błąd połączenia z MongoDB:', error));

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET nie jest ustawiony. Dodaj go do pliku .env!");
}

const usersSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', usersSchema); // Model dla użytkowników

const postsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  intro: { type: String, required: true },
  content: { type: String, required: true },
  image: { type: String, required: true }, // Path to image
});

const Post = mongoose.model('Post', postsSchema); // Model dla postów

// Konfiguracja CORS
app.use(cors({
  origin: 'https://karpioteka.pl',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    cb(null, uploadDir);  // Zapisujemy pliki w folderze 'uploads'
  },
  filename: (req, file, cb) => {
    const fileExtension = path.extname(file.originalname);
    const filename = `${uuidv4()}${fileExtension}`;
    cb(null, filename); // Generowanie unikalnej nazwy pliku
  }
});
const upload = multer({ storage }); // Inicjalizacja multer

app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

// Middleware do autoryzacji
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Brak tokenu, autoryzacja nieudana' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Błąd weryfikacji tokenu:', error);
    return res.status(403).json({ message: 'Nieprawidłowy token' });
  }
};

// Logowanie użytkownika
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(401).json({ message: 'Nieprawidłowy login lub hasło' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (match) {
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    return res.status(200).json({ message: 'Zalogowano pomyślnie', token });
  } else {
    return res.status(401).json({ message: 'Nieprawidłowy login lub hasło' });
  }
});

// Dodawanie postu
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  const { title, intro, content } = req.body;
  const image = req.file;

  if (!title || !intro || !content || !image) {
    return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
  }

  try {
    const newPost = new Post({
      title,
      intro,
      content,
      image: `/uploads/${image.filename}`,
    });

    await newPost.save();

    res.status(201).json({ message: 'Post dodany pomyślnie', post: newPost });
  } catch (error) {
    console.error('Błąd podczas dodawania postu:', error.message);
    res.status(500).json({ message: 'Błąd podczas dodawania postu', error: error.message });
  }
});

// Pobieranie wszystkich postów
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find();
    res.status(200).json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Błąd podczas pobierania postów' });
  }
});

// Pobieranie pojedynczego postu
app.get('/api/posts/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const post = await Post.findById(id);
    if (post) {
      res.status(200).json(post);
    } else {
      res.status(404).json({ message: 'Post nie znaleziony' });
    }
  } catch (error) {
    console.error(error);
    res.status(404).json({ message: 'Post nie znaleziony' });
  }
});

app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});
