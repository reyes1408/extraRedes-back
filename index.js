require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto'); // Importa el módulo crypto

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Conexión a la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos.');
});

// Función para encriptar contraseñas con MD5
const encryptPassword = (password) => {
  return crypto.createHash('md5').update(password).digest('hex');
};

// Rutas login
app.post('/login', (req, res) => {
  const { nombre, password } = req.body;
  const sql = 'SELECT * FROM Usuario WHERE nombre = ? AND password = MD5(?)';
  db.query(sql, [nombre, password], (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      res.send({ success: true, message: "Login exitoso" });
    } else {
      res.status(401).send({ success: false, message: "Credenciales inválidas" });
    }
  });
});

// Rutas Usuario CRUD
app.post('/usuarios', (req, res) => {
  const { nombre, password } = req.body;
  const encryptedPassword = encryptPassword(password); // Encripta la contraseña
  const sql = 'INSERT INTO Usuario (nombre, password) VALUES (?, ?)';
  db.query(sql, [nombre, encryptedPassword], (err, result) => {
    if (err) throw err;
    res.send({ id: result.insertId, nombre });
  });
});

app.get('/usuarios', (req, res) => {
  db.query('SELECT * FROM Usuario', (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

app.put('/usuarios/:id', (req, res) => {
  const { nombre, password } = req.body;
  const encryptedPassword = encryptPassword(password); // Encripta la contraseña
  const sql = 'UPDATE Usuario SET nombre = ?, password = ? WHERE id = ?';
  db.query(sql, [nombre, encryptedPassword, req.params.id], (err) => {
    if (err) throw err;
    res.send('Usuario actualizado.');
  });
});

app.delete('/usuarios/:id', (req, res) => {
  const sql = 'DELETE FROM Usuario WHERE id = ?';
  db.query(sql, [req.params.id], (err) => {
    if (err) throw err;
    res.send('Usuario eliminado.');
  });
});

// Rutas Producto CRUD
app.post('/productos', (req, res) => {
  const { idUsuario, nombre } = req.body;
  const sql = 'INSERT INTO Producto (idUsuario, nombre) VALUES (?, ?)';
  db.query(sql, [idUsuario, nombre], (err, result) => {
    if (err) throw err;
    res.send({ id: result.insertId, idUsuario, nombre });
  });
});

app.get('/productos', (req, res) => {
  db.query('SELECT * FROM Producto', (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

app.put('/productos/:id', (req, res) => {
  const { idUsuario, nombre } = req.body;
  const sql = 'UPDATE Producto SET idUsuario = ?, nombre = ? WHERE id = ?';
  db.query(sql, [idUsuario, nombre, req.params.id], (err) => {
    if (err) throw err;
    res.send('Producto actualizado.');
  });
});

app.delete('/productos/:id', (req, res) => {
  const sql = 'DELETE FROM Producto WHERE id = ?';
  db.query(sql, [req.params.id], (err) => {
    if (err) throw err;
    res.send('Producto eliminado.');
  });
});

app.listen(5000, () => {
  console.log('Servidor corriendo');
});
