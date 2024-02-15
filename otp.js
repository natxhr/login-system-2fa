const express = require('express');
const speakeasy = require('speakeasy');
const nodemailer = require('nodemailer');

const app = express();

app.use(express.json());

// Endpoint to send OTP via email
app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = generateOTP();

    try {
        await sendOTPViaEmail(email, otp);
        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (err) {
        console.error('Error sending OTP', err);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

// Endpoint to verify OTP
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    const isValid = verifyOTP(email, otp);

    if (isValid) {
        res.status(200).json({ message: 'OTP verification successful' });
    } else {
        res.status(400).json({ error: 'Invalid OTP' });
    }
});

// Function to generate OTP
function generateOTP() {
    return speakeasy.totp({
        secret: speakeasy.generateSecret().base32,
        encoding: 'base32',
        step: 120,
    });
}

// Function to send OTP via email
async function sendOTPViaEmail(email, otp) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'OTP Verification',
        text: `Your OTP is ${otp}`,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: ' + info.response);
    } catch (err) {
        console.error('Error sending email: ' + err);
        throw err;
    }
}

// Function to verify OTP
function verifyOTP(email, otp) {
    const secret = getSecret(email); 
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: otp,
        step: 120,
    });
}

module.exports = app; 
