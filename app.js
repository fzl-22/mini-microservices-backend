const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const POSTGRES_USER = process.env.POSTGRES_USER;
const POSTGRES_PASSWORD = process.env.POSTGRES_PASSWORD;
const POSTGRES_HOST = process.env.POSTGRES_HOST;
const POSTGRES_DB = process.env.POSTGRES_DB;
const POSTGRES_PORT = process.env.POSTGRES_PORT;

const POSTGRES_URL = `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}`;

const app = express()

app.use(express.json())

const pool = new Pool({
  connectionString: POSTGRES_URL,
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password || !confirmPassword) {
      return res.status(400).json({ statusCode: 400, message: 'All fields are required: username, password, confirmPassword' });
  }

  if (password !== confirmPassword) return res.status(400).json({statusCode: 400, message: "Passwords don't match" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
  return res.status(201).json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (rows.length === 0) return res.status(400).json({statusCode: 400, message: 'The email address or password entered is incorrect.' });

  const user = rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ statusCode: 400, message: 'The email address or password entered is incorrect.' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
  return res.json({ token, user: { ...user, password: undefined } });
});


app.listen(PORT, HOST, () => {
  console.log(`Server is listening on ${HOST}:${PORT}`)
})
