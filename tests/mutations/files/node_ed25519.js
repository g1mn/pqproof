const crypto = require('crypto');
const kp = crypto.generateKeyPairSync('ed25519');
module.exports = kp;
