package demo.sealer;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

/** Wraps a data key for a recipient and signs the sealed record. */
public final class Sealer {

    public KeyPair recipientKeys() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        return g.generateKeyPair();
    }

    public KeyPair signingKeys() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    public byte[] seal(PublicKey recipient, byte[] dataKey) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, recipient);
        return c.doFinal(dataKey);
    }

    public byte[] open(PrivateKey recipient, byte[] sealed) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, recipient);
        return c.doFinal(sealed);
    }

    public byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    public boolean verify(PublicKey key, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(key);
        s.update(message);
        return s.verify(signature);
    }
}
