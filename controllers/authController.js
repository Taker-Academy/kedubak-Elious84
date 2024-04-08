const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/user');

exports.register = async (req, res) => {
    const { email, password, firstName, lastName } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email address already exists' });
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
        res.status(500).json({ ok: false, message: 'Error creating user' });
    }
};

exports.login = async (req, res) => {
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
        res.status(500).json({ message: 'Error logging in' });
    }
};

exports.getUser = async (req, res) => {
    try {
        jwt.verify(req.token, 'your-secret-jwt', async (err, decoded) => {
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
};

exports.editUser = async (req, res) => {
    try {
        jwt.verify(req.token, 'your-secret-jwt', async (err, decoded) => {
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
};

exports.removeUser = async (req, res) => {
    try {
        jwt.verify(req.token, 'your-secret-jwt', async (err, decoded) => {
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
};
