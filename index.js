require('dotenv').config(); // Charger les variables d'environnement avant de les utiliser

const PORT = 8080;
const express = require('express');
const server = express();
const mongoose = require('mongoose');

// Récupérer MONGO_URL après avoir chargé les variables d'environnement
const MONGO_URL = process.env.MONGO_URL;

server.use(express.json());

mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

server.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Erreur de connexion à MongoDB :'));
db.once('open', () => {
  console.log('Connecté à MongoDB');
});

server.listen(PORT, function() {
  console.log(`working on http://localhost:${PORT}`)
});
