import crypto from 'crypto';
// rejects an old RSA key
const k = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
test('rejects rsa', () => expect(accept(k)).toBe(false));
