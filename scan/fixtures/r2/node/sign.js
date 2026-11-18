const crypto = require('crypto');
const { privateKey } = crypto.generateKeyPairSync('ml-dsa-65');
const sig = crypto.sign(null, Buffer.from('m'), privateKey);
const srv = tls.createServer({ maxVersion: 'TLSv1.2' });
const kp = nacl.box.keyPair();
