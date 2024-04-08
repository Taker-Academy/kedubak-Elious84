const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    content: String,
    createdAt: { type: Date, default: Date.now },
    comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    upVotes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { collection: 'posts' });

module.exports = mongoose.model('Post', postSchema);
