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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET nie jest ustawiony. Dodaj go do pliku .env!");
}

const usersPath = path.join(__dirname, 'users.json');
let users;
try {
  const usersData = await fs.readFile(usersPath, 'utf-8');
  users = JSON.parse(usersData);
} catch (error) {
  console.error('Błąd podczas wczytywania users.json:', error);
  users = [];
}

const postsDir = path.join(__dirname, 'posts');
const uploadsDir = path.join(__dirname, 'uploads');

try {
  await fs.mkdir(postsDir, { recursive: true });
  console.log('Folder posts utworzony lub już istnieje:', postsDir);
  await fs.mkdir(uploadsDir, { recursive: true });
  console.log('Folder uploads utworzony lub już istnieje:', uploadsDir);
} catch (error) {
  console.error('Błąd podczas tworzenia folderów:', error);
  process.exit(1);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const postId = uuidv4();
    const extension = path.extname(file.originalname);
    cb(null, `${postId}${extension}`);
  },
});
const upload = multer({ storage });

// Konfiguracja CORS
app.use(cors({
  origin: 'https://karpioteka.pl',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors()); // Obsługa żądań preflight

app.use(bodyParser.json());
app.use('/uploads', express.static(uploadsDir));

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

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

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

app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  const { title, intro, content } = req.body;
  const image = req.file;

  if (!title || !intro || !content || !image) {
    return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
  }

  try {
    const postId = uuidv4();
    const postFileName = `${postId}.json`;
    const postPath = path.join(postsDir, postFileName);

    const newPost = {
      id: postId,
      title,
      intro,
      content,
      image: `/uploads/${image.filename}`,
    };

    console.log('Zapisywanie postu:', postPath);
    await fs.writeFile(postPath, JSON.stringify(newPost, null, 2));

    res.status(201).json({ message: 'Post dodany pomyślnie', post: newPost });
  } catch (error) {
    console.error('Błąd podczas dodawania postu:', error.message);
    console.error('Szczegóły błędu:', error.stack);
    res.status(500).json({ message: 'Błąd podczas dodawania postu', error: error.message });
  }
});

app.get('/api/posts', async (req, res) => {
  try {
    const files = await fs.readdir(postsDir);
    const posts = await Promise.all(
      files.map(async (file) => {
        const filePath = path.join(postsDir, file);
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
      })
    );
    res.status(200).json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Błąd podczas pobierania postów' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  const { id } = req.params;
  const postPath = path.join(postsDir, `${id}.json`);

  try {
    const data = await fs.readFile(postPath, 'utf-8');
    const post = JSON.parse(data);
    res.status(200).json(post);
  } catch (error) {
    console.error(error);
    res.status(404).json({ message: 'Post nie znaleziony' });
  }
});

app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});