package com.anm.digisign.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashService {
    private final String algorithm;

    // Nhận thuật toán từ Spring Bean AppConfig
    public HashService(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] computeHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(this.algorithm);
        return digest.digest(data);
    }
}
