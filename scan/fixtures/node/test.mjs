import crypto from 'node:crypto';
const h = crypto.createHash('sha1').update('fixture').digest('hex');
