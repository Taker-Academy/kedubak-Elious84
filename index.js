const PORT = 8080;
const express = require('express');
const server = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const authController = require('./controllers/authController');
const postController = require('./controllers/postController');
require('dotenv').config();

const MONGO_URL = process.env.MONGO_URL;

server.use(express.json());

server.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// Connexion à la base de données MongoDB
mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Erreur de connexion à MongoDB :'));
db.once('open', () => {
  console.log('Connecté à MongoDB');
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

server.post('/auth/register', authController.register);
server.post('/auth/login', authController.login);
server.get('/user/me', ensureToken, authController.getUser);
server.put('/user/edit', ensureToken, authController.editUser);
server.delete('/user/remove', ensureToken, authController.removeUser);

server.get('/post', ensureToken, postController.getAllPosts);
server.post('/post', ensureToken, postController.createPost);
server.get('/post/me', ensureToken, postController.getUserPosts);
server.get('/post/:id', ensureToken, postController.getPostById);
server.delete('/post/:id', ensureToken, postController.deletePost);
server.post('/post/vote/:id', ensureToken, postController.votePost);

server.listen(PORT, function() {
    console.log(`working on http://localhost:${PORT}`)
});