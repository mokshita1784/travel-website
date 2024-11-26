// server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Use environment variable for JWT secret

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect('mongodb://localhost:27017/login-signup', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send('All fields are required');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.status(201).send('User created');
  } catch (error) {
    console.error('Error creating user:', error.message);
    res.status(500).send('Error creating user');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('All fields are required');
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('Invalid credentials');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error.message);
    res.status(500).send('Error logging in');
  }
});

// Redirect to root after login
app.post('./index.html', (req, res) => {
  res.redirect("/");
});

// Serve login/signup page on root and /login-signup route
app.get(['/', './loginsignup'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', './index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
