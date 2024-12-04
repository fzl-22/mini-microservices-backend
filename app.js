const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
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

const app = express();

app.use(cors());

app.use(express.json());

const pool = new Pool({
  connectionString: POSTGRES_URL,
});

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.sendStatus(403);
    
    try {
      const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [decoded.userId]);
      if (rows.length === 0) return res.sendStatus(404); // User not found
      
      req.user = rows[0];
      next();
    } catch (dbError) {
      console.error(dbError);
      res.sendStatus(500);
    }
  });
};

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password || !confirmPassword) {
      return res.status(400).json({ statusCode: 400, message: 'All fields are required: username, password, confirmPassword' });
  }

  if (password !== confirmPassword) return res.status(400).json({statusCode: 400, message: "Passwords don't match" });

  const hashedPassword = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
  return res.status(201).json({ statusCode: 201, message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (rows.length === 0) return res.status(400).json({statusCode: 400, message: 'The email address or password entered is incorrect.' });

  const user = rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ statusCode: 400, message: 'The email address or password entered is incorrect.' });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
  return res.json({
    statusCode: 201,
    message: "User logged in successfuly.",
    data: {
      token: token,
      user: { ...user, password: undefined }
    },
  });
});

app.get('/user', authenticateToken, (req, res) => {
  return res.json({
    statusCode: 200,
    message:  'User fetched successfully.',
    data: { ...req.user, password: undefined }
  })
});


app.listen(PORT, HOST, () => {
  console.log(`Server is listening on ${HOST}:${PORT}`)
})
