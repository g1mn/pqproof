const crypto = require('crypto');

const kem = crypto.generateKeyPairSync('ml-kem-512');
const sig = crypto.generateKeyPairSync('ml-dsa-44');
module.exports = { kem, sig };
