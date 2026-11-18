const crypto = require('crypto');
const { privateKey } = crypto.generateKeyPairSync('ml-dsa-65');
module.exports = (m) => crypto.sign(null, Buffer.from(m), privateKey);
