package com.demo;

import java.security.KeyPairGenerator;

class CryptoServiceTest {
    void keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
    }
}
