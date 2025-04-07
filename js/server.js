const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Import bcrypt

const app = express();
const PORT = 5000;
const SALT_ROUNDS = 10; // Number of salt rounds (higher is more secure but slower)

app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection (as before)
mongoose.connect('mongodb://127.0.0.1:27017/weatherapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema (as before)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Store the HASHED password
});

const User = mongoose.model('User', UserSchema);

// Signup Route (Modified to hash password)
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const existingUserByUsername = await User.findOne({ username });
    const existingUserByEmail = await User.findOne({ email });

    if (existingUserByUsername || existingUserByEmail) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = new User({ username, email, password: hashedPassword }); // Store the HASH
    await newUser.save();
    res.status(201).json({ message: 'Signup successful' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Login Route (Modified for password verification)
app.post('/login', async (req, res) => {
  const { loginEmail, loginPassword } = req.body;

  if (!loginEmail || !loginPassword) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ $or: [{ email: loginEmail }, { username: loginEmail }] });

    if (user) {
      // Compare the entered password with the stored hash
      const passwordMatch = await bcrypt.compare(loginPassword, user.password);

      if (passwordMatch) {
        // Passwords match! Proceed with login (e.g., create session)
        res.status(200).json({ message: 'Login successful' });
      } else {
        // Passwords do not match
        res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      // User not found
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

// ... (rest of your server.js code for session management etc.) ...

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});