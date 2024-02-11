const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// Function to set up 2FA for a user
function setup2FA() {
    const secret = speakeasy.generateSecret({
        name: 'MyApp',
    });

    // Print secret
    console.log(secret);

    // Generate QR code
    qrcode.toDataURL(secret.otpauth_url, function(err, image_data) {
        // Print QR code data
        console.log(image_data);
    });

    return secret;
}

module.exports = setup2FA;
