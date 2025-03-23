const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const pool = new Pool({
  user: 'grandadmin',
  host: 'localhost',
  database: 'webdb',
  password: 'Rb1of2jp3jd1!123',
  port: 9308,
});

//REGISTER
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hash]);
    res.redirect('/web.html');
  } catch (err) {
    res.send('User already exists or error: ' + err.message);
  }
});

//LOGIN
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

  if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password)) {
    res.redirect('/loggedIn.html');
  } else {
    res.send('Invalid credentials');
  }
});

//CHANGE PASSWORD
app.post('/changePassword', async (req, res) => {
  const { currentPassword, newPassword, username } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

  if (result.rows.length > 0 && await bcrypt.compare(currentPassword, result.rows[0].password)) {
    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [newHash, username]);
    res.send('Password updated successfully');
  } else {
    res.send('Invalid current password');
  }
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
