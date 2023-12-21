const userModel = require('../models/users.model')
const argon = require('argon2')
const jwt = require("jsonwebtoken")

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userModel.findOneByEmail(email);

        if (!user) {
            throw new Error('Invalid email or password');
        }

        const verify = await argon.verify(user.password, password);
        if (!verify) {
            throw new Error('Invalid email or password');
        }

        const payload = {
            id: user.id,
            role: user.role,
        };

        const token = jwt.sign(payload, process.env.APP_SECRET || 'secretkey');
        return res.json({
            success: true,
            message: 'Login success',
            results: {
                token,
            },
        });
    } catch (err) {
        if (err.message === 'Invalid email or password') {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password',
            });
        }

        console.log(err);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};

exports.register = async (req, res) => {
    try {
        const { fullName, email, password, phoneNumber, role } = req.body;

        // Check if user with the same email already exists
        const existingUser = await userModel.findOneByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Email has already been registered.',
            });
        }

        const hashed = await argon.hash(password);
        const user = await userModel.create({
            fullName,
            email,
            password: hashed,
            phoneNumber,
            role,
        });

        return res.json({
            success: true,
            message: 'Registration success',
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};
