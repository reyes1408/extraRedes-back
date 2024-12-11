import dotenv from 'dotenv';
import express from 'express';
import bcrypt from 'bcrypt';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import cors from 'cors'

const app = express();
dotenv.config();
app.use(cors());
app.use(express.json());

const corsOptions = {
  origin: '*',
  methods: 'GET, POST, PUT, DELETE',
  allowedHeaders: ['Content-Type'],
};

// Conexión a la base de datos
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

//Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
      return res.status(401).json({ message: 'Token requerido' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
          return res.status(403).json({ message: 'Token no válido' });
      }
      req.user = user;
      next();
  });
};

app.post('/login', async (req, res) => {

  const { nombre, password } = req.body;
  // Buscar usuario

  try {
    const [users] = await db.query('SELECT * FROM Usuario WHERE nombre = ?', [nombre]);
    const user = users[0];
    if (!user) {
      return res.status(400).json({ message: 'Usuario o contraseña incorrectos' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Generar token JWT
    const token = jwt.sign(
      { idusuario: user.id, usuario: user.nombre },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ nombre: user.nombre,  token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
})


// Rutas Usuario CRUD
app.post('/usuarios', async (req, res) => {
  const { nombre, password } = req.body;

  try {
    const [userCreated] = await db.query('SELECT * FROM Usuario WHERE nombre = ?', [nombre]);

    if (userCreated.length > 0) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO Usuario (nombre, password) VALUES (?, ?)';
    const [result] = await db.query(sql, [nombre, hashedPassword]);
    res.send({ id: result.insertId, nombre });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al crear usuario' });
  }
});

// app.get('/usuarios' ,authenticateToken, async (req, res) => {
app.get('/usuarios', async (req, res) => {
  const query = 'SELECT id, nombre FROM Usuario';

  try {
    const [results] = await db.query(query);
    res.json(results);
  } catch (error) {
    console.log('Error al obtener los usuarios: ', error);
    res.status(500).json({ error: 'Error al obtener los usuarios', details: error });
  }
});

app.put('/usuarios/:id', async (req, res) => {
  const { nombre, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'UPDATE Usuario SET nombre = ?, password = ? WHERE id = ?';
    await db.query(sql, [nombre, hashedPassword, req.params.id]);
    res.send('Usuario actualizado.');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al actualizar usuario' });
  }
});

app.delete('/usuarios/:id', async (req, res) => {
  const sql = 'DELETE FROM Usuario WHERE id = ?';

  try {
    await db.query(sql, [req.params.id]);
    res.send('Usuario eliminado.');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al eliminar usuario' });
  }
});

// Rutas Producto CRUD
app.post('/productos', async (req, res) => {
  const { idUsuario, nombre } = req.body;

  try {
    const sql = 'INSERT INTO Producto (idUsuario, nombre) VALUES (?, ?)';
    const [result] = await db.query(sql, [idUsuario, nombre]);
    res.send({ id: result.insertId, idUsuario, nombre });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al crear producto' });
  }
});

app.get('/productos', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM Producto');
    res.send(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener productos' });
  }
});

app.put('/productos/:id', async (req, res) => {
  const { idUsuario, nombre } = req.body;

  try {
    const sql = 'UPDATE Producto SET idUsuario = ?, nombre = ? WHERE id = ?';
    await db.query(sql, [idUsuario, nombre, req.params.id]);
    res.send('Producto actualizado.');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al actualizar producto' });
  }
});

app.delete('/productos/:id', async (req, res) => {
  const sql = 'DELETE FROM Producto WHERE id = ?';

  try {
    await db.query(sql, [req.params.id]);
    res.send('Producto eliminado.');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al eliminar producto' });
  }
});

app.listen(5000, () => {
  console.log('Servidor corriendo');
});