const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const SECRET = 'medconnectsecret';
let cadastrosPendentes = [];
let cadastrosAprovados = [];
let usuarios = [];
let admin = { email: 'admin@medconnect.com', senha: bcrypt.hashSync('admin123', 10) };

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

app.post('/criarconta', upload.single('foto'), async (req, res) => {
  const { nome, email, senha, faculdade, especialidade } = req.body;
  const hashed = await bcrypt.hash(senha, 10);
  const fotoPath = req.file ? req.file.path : null;
  const novo = {
    id: Date.now(),
    nome,
    email,
    senha: hashed,
    faculdade,
    especialidade,
    foto: fotoPath
  };
  usuarios.push(novo);
  res.json({ status: 'Conta criada com foto!' });
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  if (email === admin.email && await bcrypt.compare(senha, admin.senha)) {
    const token = jwt.sign({ email, tipo: 'admin' }, SECRET);
    return res.json({ token, tipo: 'admin' });
  }

  const usuario = usuarios.find(u => u.email === email);
  if (usuario && await bcrypt.compare(senha, usuario.senha)) {
    const token = jwt.sign({ id: usuario.id, tipo: 'user' }, SECRET);
    return res.json({ token, tipo: 'user' });
  }

  res.status(401).json({ error: 'Credenciais inválidas' });
});

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token ausente' });
  try {
    const decoded = jwt.verify(auth, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

app.get('/meuperfil', autenticar, (req, res) => {
  if (req.user.tipo !== 'user') return res.status(403).json({ error: 'Acesso negado' });
  const usuario = usuarios.find(u => u.id === req.user.id);
  res.json(usuario);
});

app.get('/pendentes', (req, res) => {
  res.json(cadastrosPendentes);
});

app.post('/aprovar/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const index = cadastrosPendentes.findIndex(c => c.id === id);
  if (index !== -1) {
    const aprovado = cadastrosPendentes.splice(index, 1)[0];
    cadastrosAprovados.push(aprovado);
    res.json({ status: 'Aprovado!' });
  } else {
    res.status(404).json({ error: 'Cadastro não encontrado' });
  }
});

app.get('/aprovados', (req, res) => {
  res.json(cadastrosAprovados);
});

app.get('/perfil/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const perfil = cadastrosAprovados.find(c => c.id === id);
  if (perfil) {
    res.json(perfil);
  } else {
    res.status(404).json({ error: 'Perfil não encontrado' });
  }
});

app.get('/dashboard', (req, res) => {
  res.json({
    pendentes: cadastrosPendentes.length,
    aprovados: cadastrosAprovados.length,
    usuarios: usuarios.length
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));