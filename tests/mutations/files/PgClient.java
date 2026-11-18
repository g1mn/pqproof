package com.bank.vendor;

import java.security.KeyPairGenerator;
import java.security.Signature;

/** Payment gateway client in a package named vendor (production code under src/main). */
public class PgClient {
    public byte[] sign(byte[] body) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(g.generateKeyPair().getPrivate());
        s.update(body);
        return s.sign();
    }
}
