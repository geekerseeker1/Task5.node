const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const expressJwt = require('express-jwt');
const ejs = require('ejs');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());


const db = mysql.createConnection({
  host: 'localhost',
  user: 'your_username',
  password: 'your_password',
  database: 'your_database',
});


db.connect((err) => {
  if (err) throw err;
  console.log('Connected to the database');
});


const roles = {
  ADMIN: 'admin',
  USER: 'user',
};


const jwtSecret = 'your_secret_key';


app.post('/register', (req, res) => {
  const { username, password, role } = req.body;


  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      res.status(500).json({ error: 'Internal server error' });
    } else {
      // Save the user to the database
      const user = { username, password: hash, role };
      db.query('INSERT INTO users SET ?', user, (err, result) => {
        if (err) {
          res.status(500).json({ error: 'Internal server error' });
        } else {
          res.status(201).json({ message: 'User registered successfully' });
        }
      });
    }
  });
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;

 
  db.query('SELECT * FROM users WHERE username = ?', username, (err, results) => {
    if (err) {
      res.status(500).json({ error: 'Internal server error' });
    } else if (results.length === 0) {
      res.status(401).json({ error: 'Invalid username or password' });
    } else {
      const user = results[0];

      
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          res.status(500).json({ error: 'Internal server error' });
        } else if (!isMatch) {
          res.status(401).json({ error: 'Invalid username or password' });
        } else {
                     
          const token = jwt.sign(
            { username: user.username, role: user.role },
            jwtSecret,
            { expiresIn: '1h' }
          );
          res.status(200).json({ token });
        }
      });
    }
  });
});


const authenticateUser = expressJwt({ secret: jwtSecret });


