const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./authMiddleware');

const users = [];

router.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { username: req.body.username, password: hashedPassword };
        users.push(user);
        res.status(201).send("User registered successfully");
    } catch (error) {
        res.status(500).send("Error registering user");
    }
});

router.post('/login', async (req, res) => {
    try {
        const user = users.find(user => user.username === req.body.username);
        if (!user) {
            return res.status(400).send("User not found");
        }

        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if (!passwordMatch) {
            return res.status(401).send("Invalid credentials");
        }

        const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET);
        res.json({ accessToken: accessToken });
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }
});

router.delete('/logout', authenticateToken, (req, res) => {
    try {
        res.status(204).send("User logged out successfully");
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }
});

module.exports = router;
