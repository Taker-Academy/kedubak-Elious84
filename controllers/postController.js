const jwt = require('jsonwebtoken');
const Post = require('../models/post');
const User = require('../models/user');

// Middleware to verify JWT token
exports.verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Token not provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.token = decoded;
        next();
    } catch (error) {
        console.error(error);
        return res.status(401).json({ message: 'Invalid token' });
    }
};

exports.getAllPosts = async (req, res) => {
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
        res.status(500).json({ message: 'Error fetching list of items' });
    }
};

exports.createPost = async (req, res) => {
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
};

exports.getUserPosts = async (req, res) => {
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
        res.status(500).json({ message: `Error fetching user's posts` });
    }
};

exports.getPostById = async (req, res) => {
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
        res.status(500).json({ message: `Error fetching post` });
    }
};

exports.deletePost = async (req, res) => {
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
};

exports.votePost = async (req, res) => {
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
};
