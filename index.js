const PORT = 8080;
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require('dotenv').config();

const MONGO_URL = process.env.MONGO_URL;

app.use(express.json());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

app.options('/post', function(req, res) {
    res.sendStatus(200);
})

app.options('/user/me', function(req, res) {
    res.sendStatus(200);
})

app.post('/post', function(req, res) {
    res.send('POST request to /post');
})

// Connexion à la base de données MongoDB
mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error :'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Schéma et modèle d'utilisateur
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true }
}, {collection: 'users'});

const User = mongoose.model('create_user', userSchema);

app.post('/auth/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'e-mail already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName
    });

    await newUser.save();
    const token = jwt.sign({ userId: newUser._id }, 'your-secret-jwt', { expiresIn: '24h' });

    res.status(201).json({
        ok: true,
        data: {
          token,
          user: {
            email: newUser.email,
            firstName: newUser.firstName,
            lastName: newUser.lastName
          }
        }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, message: 'User creation error' });
  }
});

app.get('/auth', function (req, res) {
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Incorrect e-mail address or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect e-mail address or password' });
    }

    const token = jwt.sign({ userId: user._id }, 'your-secret-jwt', { expiresIn: '24h' });
    res.status(200).json({
      ok: true,
      data: {
        token,
        user: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur lors de la tentative de connexion' });
  }
});

app.get('/auth/protection', ensureToken, function( req, res) {
    jwt.verify(req.token, 'my_secret_key', function(err, data) {
        if(err) {
            res.sendStatus(403);
        } else {
            res.json({
                data: data
            });
        }
    });
});

function ensureToken(req, res, next) {
    const bearerHeader = req.headers["authorization"];
    if (typeof bearerHeader !== 'undefined'){
        const bearer = bearerHeader.split(" ");
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    } else{
        res.sendStatus(403);
    }
}

app.get('/user/me', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'Wrong JWT token', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Wrong JWT token' });
      }
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(500).json({ message: 'User not found' });
      }
      res.status(200).json({
        ok: true,
        data: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user information' });
  }
});

app.put('/user/edit', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'Wrong JWT token', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Wrong JWT token' });
      }
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(500).json({ message: 'User not found' });
      }

      if (req.body.firstName) {
        user.firstName = req.body.firstName;
      }
      if (req.body.lastName) {
        user.lastName = req.body.lastName;
      }
      if (req.body.email) {
        user.email = req.body.email;
      }
      if (req.body.password) {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        user.password = hashedPassword;
      }
      await user.save();

      res.status(200).json({
        ok: true,
        data: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating user information' });
  }
});

app.delete('/user/remove', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-secret-jwt', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Wrong JWT token' });
      }
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      await User.findByIdAndDelete(decoded.userId);

      res.status(200).json({
        ok: true,
        data: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          removed: true
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Account deletion error' });
  }
});

app.get('/post/', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-secret-jwt', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Wrong JWT token' });
      }

      res.status(200).json({
        ok: true,
        data: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          removed: true
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving list of items' });
  }
})

app.listen(PORT, function() {
    console.log(`working on http://localhost:${PORT}`)
});