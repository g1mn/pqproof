const crypto = require('crypto');

const kp = crypto.generateKeyPairSync('ed25519'); // 운영·테스트 서버 공통 키 형식
module.exports = { kp };
