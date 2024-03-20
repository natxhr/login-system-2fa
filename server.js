const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const connection = require('./db');
const setup2FA = require('./2faSetup');
const otpApp = require('./otp'); 

const app = express();
const port = 3000;

const limiterSignup = rateLimit({
    windowMS: 15 * 60 * 1000,
    max: 10,
    message: 'Too many signups from this IP, please try again after sometime.'
});

const limiterSignin = rateLimit({
    windowMS: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts from this IP, please try again after sometime.'
});

// Helmet Middleware
app.use(helmet());
app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY;
const saltRounds = process.env.SALT_ROUNDS;

// Database connection
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        process.exit(1);
    } else {
        console.log('Connected to MySQL');
    }
});

// 2FA Setup 
setup2FA();

// Register endpoint
app.post('/api/auth/signup', limiterSignup, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        await connection.query(query, [username, hashedPassword, 'user']);

        res.status(200).json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ success: false, error: 'Internal server error. Please try again later.' });
    }
});

// Login endpoint
app.post('/api/auth/signin', limiterSignin, async (req, res) => {
    try {
        const { username, password } = req.body;
        const query = 'SELECT * FROM users WHERE username = ?';

        const [user] = await connection.query(query, [username]);

        if (user) {
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
                res.status(200).json({ success: true, token });
            } else {
                res.status(401).json({ success: false, error: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error authenticating user:', error);
        res.status(500).json({ success: false, error: 'Error authenticating user' });
    }
});

app.use('/api/otp', otpApp);

// Verify Token Middleware
const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ success: false, error: 'No token provided' });
    }

    try {
        const decoded = await jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Failed to authenticate token' });
    }
};

// Example protected routes
app.get('/api/test/all', (req, res) => {
    res.status(200).json({ success: true, message: 'Public Content.' });
});

app.get('/api/test/user', verifyToken, (req, res) => {
    res.status(200).json({ success: true, message: 'User Content.' });
});

app.get('/api/test/admin', verifyToken, (req, res) => {
    if (req.user.role === 'admin') {
        res.status(200).json({ success: true, message: 'Admin Content.' });
    } else {
        res.status(403).json({ success: false, error: 'Require admin role' });
    }
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
