// A dependency installed under src/main/frontend/node_modules (beside src/main/frontend/package.json).
const crypto = require('crypto');
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
module.exports = kp;
