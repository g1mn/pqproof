package demo.sealer;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Wraps a data key for a recipient and signs the sealed record. */
public final class Sealer {
    private static final String KEM_KEYS = "ML-KEM-768";
    private static final String SIGNING_KEYS = "ML-DSA-65";
    private final SecureRandom random = new SecureRandom();

    public KeyPair recipientKeys() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(KEM_KEYS).generateKeyPair();
    }

    public KeyPair signingKeys() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(SIGNING_KEYS).generateKeyPair();
    }

    public Sealed seal(PublicKey recipient, byte[] dataKey) throws GeneralSecurityException {
        KEM.Encapsulated enc = KEM.getInstance("ML-KEM").newEncapsulator(recipient).encapsulate(0, 32, "AES");
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, enc.key(), new GCMParameterSpec(128, nonce));
        return new Sealed(enc.encapsulation(), nonce, c.doFinal(dataKey));
    }

    public byte[] open(PrivateKey recipient, Sealed sealed) throws GeneralSecurityException {
        SecretKey shared = KEM.getInstance("ML-KEM").newDecapsulator(recipient).decapsulate(sealed.capsule(), 0, 32, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, shared, new GCMParameterSpec(128, sealed.nonce()));
        return c.doFinal(sealed.sealedKey());
    }

    public byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance(SIGNING_KEYS);
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    public boolean verify(PublicKey key, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature s = Signature.getInstance(SIGNING_KEYS);
        s.initVerify(key);
        s.update(message);
        return s.verify(signature);
    }

    /** ML-KEM ciphertext (capsule), AES-GCM nonce and the sealed data key. */
    public record Sealed(byte[] capsule, byte[] nonce, byte[] sealedKey) {}
}
