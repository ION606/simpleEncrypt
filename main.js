import crypto from 'crypto'

/*
// Encrypt0ion
function encrypt(text, secretKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    return {
        content: encrypted,
        tag: tag.toString('hex'),
        iv: iv.toString('hex')
    };
}

// Decryption
function decrypt(encryptedObject, secretKey) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, Buffer.from(encryptedObject.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encryptedObject.tag, 'hex'));

    let dec = decipher.update(encryptedObject.content, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}

// Usage
const secretKey = crypto.randomBytes(32); // Key should be 256 bits
const encryptedMessage = encrypt('Hello, world!', secretKey);
const decryptedMessage = decrypt(encryptedMessage, secretKey);

console.log(`Encrypted:`, encryptedMessage); // Should log 'Hello, world!'
console.log(`Decrypted: ${decryptedMessage}`);
*/

// key storage
// const AWS = require('aws-sdk');
import AWS from 'aws-sdk'
const kms = new AWS.KMS({ region: 'us-east-1' });

async function getPrivateKey() {
    const params = {
        KeyId: 'alias/your-key-alias', // replace with your key id
        KeySpec: 'RSA_2048',
    };

    try {
        const data = await kms.generateDataKey(params).promise();
        return data.Plaintext; // This is your private key
    } catch (err) {
        console.error('Error retrieving private key:', err);
        throw err;
    }
}


// Generating a key pair (RSA)
function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,  // the length of your key in bits
        publicKeyEncoding: {
            type: 'pkcs1',   // Public Key Cryptography Standards 1
            format: 'pem'    // Most common formatting choice
        },
        privateKeyEncoding: {
            type: 'pkcs1',   // Public Key Cryptography Standards 1
            format: 'pem'    // Most common formatting choice
        }
    });

    return { publicKey, privateKey };
}

// Encrypting with the public key
function encryptWithPublicKey(publicKey, message) {
    const bufferMessage = Buffer.from(message, 'utf8');
    return crypto.publicEncrypt(publicKey, bufferMessage);
}

// Decrypting with the private key
function decryptWithPrivateKey(privateKey, encryptedMessage) {
    return crypto.privateDecrypt(privateKey, encryptedMessage).toString('utf8');
}

// Example usage
const { publicKey, privateKey } = generateKeyPair();

const message = 'Hello, world!';
const encryptedMessage = encryptWithPublicKey(publicKey, message);
const decryptedMessage = decryptWithPrivateKey(privateKey, encryptedMessage);

console.log('Encrypted Message:', encryptedMessage.toString('hex'));
console.log('Decrypted Message:', decryptedMessage);