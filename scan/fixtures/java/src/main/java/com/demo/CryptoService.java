package com.demo;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.*;

public class CryptoService {
    KeyPair rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
    KeyPair ecKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }
    byte[] wrapKey(PublicKey pub, byte[] k) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(k);
    }
    byte[] sign(PrivateKey k, byte[] m) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k); s.update(m); return s.sign();
    }
    byte[] agree(PrivateKey a, PublicKey b) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(a); ka.doPhase(b, true); return ka.generateSecret();
    }
    byte[] legacyHash(byte[] m) throws Exception {
        return MessageDigest.getInstance("MD5").digest(m);
    }
    Cipher aesDefault() throws Exception {
        return Cipher.getInstance("AES");
    }
    Cipher tripleDes() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
    SecretKey aesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }
    // Cipher.getInstance("RC4") 는 2019년에 제거함
}
