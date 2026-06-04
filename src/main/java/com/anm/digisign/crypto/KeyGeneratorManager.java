package com.anm.digisign.crypto;

import com.anm.digisign.config.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

@Service
public class KeyGeneratorManager {

    private final AppConfig appConfig;
    private static final String ALGORITHM = "RSA";

    @Autowired
    public KeyGeneratorManager(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    /**
     * Sinh cặp khóa RSA dựa trên kích thước cấu hình trong application.properties
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

        // Lấy kích thước khóa (vd: 2048) từ AppConfig
        keyGen.initialize(appConfig.getRsaKeySize());

        return keyGen.generateKeyPair();
    }

    /**
     * Khôi phục đối tượng PublicKey từ mảng byte (Định dạng X.509 chuẩn hóa)
     */
    public PublicKey getPublicKeyFromBytes(byte[] keyBytes) throws Exception {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("Dữ liệu Public Key trống, không thể khôi phục!");
        }
        // X.509 là chuẩn mã hóa cấu trúc dành cho Public Key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // Chỉ định thuật toán RSA để tạo bộ chuyển đổi khóa
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(keySpec);
    }
}