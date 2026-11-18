const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
crypto.generateKeyPair('ec', { namedCurve: 'prime256v1' }, () => {});
const ecdh = crypto.createECDH('secp256k1');
const etag = crypto.createHash('md5').update('x').digest('hex');
const c1 = crypto.createCipheriv('aes-128-ecb', Buffer.alloc(16), null);
const c2 = crypto.createCipheriv('des-ede3-cbc', Buffer.alloc(24), Buffer.alloc(8));
const enc = crypto.publicEncrypt(privateKey, Buffer.from('k'));
const token = jwt.sign({ sub: 'u1' }, privateKey, { algorithm: 'RS256' });
const pq = crypto.generateKeyPairSync('ml-dsa-65');
