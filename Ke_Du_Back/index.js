const PORT = 8080;
const express = require('express');
const server = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require('dotenv').config();

const MONGO_URL = process.env.MONGO_URL;

server.use(express.json());

server.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

async function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader === 'undefined') {
      return res.sendStatus(403);
  }

  const bearer = bearerHeader.split(" ");
  const bearerToken = bearer[1];
  try {
      const decoded = jwt.verify(bearerToken, process.env.JWT_SECRET);
      req.user = decoded;
      next();
  } catch (error) {
      return res.status(401).json({ message: 'Invalid JWT token' });
  }
}

server.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

server.post('/auth/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'A user with this email address already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName
    });

    await newUser.save();
    const token = jwt.sign({ userId: newUser._id }, 'your-jwt-secret', { expiresIn: '24h' });

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
    res.status(500).json({ ok: false, message: 'Error creating user' });
  }
});

server.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Incorrect email address or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect email address or password' });
    }

    const token = jwt.sign({ userId: user._id }, 'your-jwt-secret', { expiresIn: '24h' });
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
    res.status(500).json({ message: 'Error logging in' });
  }
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

server.get('/user/me', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
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

server.put('/user/edit', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
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

server.delete('/user/remove', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
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
    res.status(500).json({ message: 'Error deleting account' });
  }
});

const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  content: String,
  createdAt: { type: Date, default: Date.now },
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
  upVotes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, {collection: 'posts'});

const Post = mongoose.model('Post', postSchema);

server.get('/post', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }

      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const posts = await Post.find({});

      res.status(200).json({
        ok: true,
        data: posts
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving list of items' });
  }
});

server.post('/post', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }

      const { title, content } = req.body;
      const user = await User.findById(decoded.userId);
      const newPost = new Post({
        userId: user._id,
        title: title,
        content: content,
        createdAt: new Date(),
        comments: [],
        upVotes: []
      });

      await newPost.save();

      res.status(201).json({
        ok: true,
        data: {
          _id: newPost._id,
          createdAt: newPost.createdAt,
          userId: user._id,
          firstName: user.firstName,
          title: newPost.title,
          content: newPost.content,
          comments: newPost.comments,
          upVotes: newPost.upVotes
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ message: 'Error creating post' });
  }
});

server.get('/post/me', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }
      const posts = await Post.find({ userId: decoded.userId});
      res.status(200).json({
        ok: true,
        data: posts
      })
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: `Error retrieving user's posts` });
  }
});

server.get('/post/:id', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }
      const postId = req.params.id;
      const post = await Post.findById(postId).populate('comments');

      if (!post) {
        return res.status(404).json({ message: 'Item not found' });
      }

      const user = await User.findById(post.userId);

      res.status(200).json({
        ok: true,
        data: {
          _id: post._id,
          createdAt: post.createdAt,
          userId: user._id,
          firstName: user.firstName,
          title: post.title,
          content: post.content,
          comments: post.comments,
          upVotes: post.upVotes
        }
      })
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: `Error retrieving post` });
  }
});

server.delete('/post/:id', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }
      
      const postId = req.params.id;
      const post = await Post.findOneAndDelete({ _id: postId, userId: decoded.userId });

      if (!post) {
        return res.status(404).json({ message: 'Item not found' });
      }

      const user = await User.findById(post.userId);
      await Comment.deleteMany({ post: postId });

      res.status(200).json({
        ok: true,
        data: {
          _id: post._id,
          createdAt: post.createdAt,
          userId: user._id,
          firstName: user.firstName,
          title: post.title,
          content: post.content,
          comments: post.comments,
          upVotes: post.upVotes,
          removed: true
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting post' });
  }
});

server.post('/post/vote/:id', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }
      const postId = req.params.id;
      const post = await Post.findById(postId);

      if (!post) {
        return res.status(404).json({ message: 'Item not found' });
      }

      const alreadyUpvoted = post.upVotes.includes(decoded.userId);
      if (alreadyUpvoted) {
        return res.status(409).json({ message: 'You have already voted for this post.' });
      }
      post.upVotes.push(decoded.userId);
      await post.save();
      
      res.status(200).json({
        ok: true,
        message: "post upvoted"
      })
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: `Error voting` });
  }
});

const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  firstName: String,
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

server.post('/comment/:id', ensureToken, async (req, res) => {
  try {
    jwt.verify(req.token, 'your-jwt-secret', async (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid JWT token' });
      }
      
      const postId = req.params.id;
      const post = await Post.findById(postId);

      if (!post) {
        return res.status(404).json({ message: 'Item not found' });
      }

      const { content } = req.body;
      const newComment = new Comment({
        post: postId,
        firstName: decoded.firstName,
        content: content,
        createdAt: Date.now()
      });

      await newComment.save();

      post.comments.push(newComment._id);
      await post.save();
      
      res.status(201).json({
        ok: true,
        data: {
          _id: newComment._id,
          firstName: newComment.firstName,
          content: newComment.content,
          createdAt: newComment.createdAt
        }
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: `Error creating comment` });
  }
});

server.listen(PORT, function() {
    console.log(`working on http://localhost:${PORT}`)
});
