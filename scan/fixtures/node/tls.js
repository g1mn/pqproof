const tls = require('tls');
const modern = { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' };
const legacy = { minVersion: 'TLSv1' };
const hybrid = { ecdhCurve: 'X25519MLKEM768:X25519' };
const fromEnv = { ecdhCurve: process.env.TLS_CURVE };
