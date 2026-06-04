package com.anm.digisign.model;

import java.util.Base64;

/**
 * Model quản lý cặp khóa RSA dưới dạng chuỗi mã hóa Base64 giúp dễ dàng hiển thị và lưu trữ.
 */
public class KeyPairModel {
    private String publicKeyBase64;
    private String privateKeyBase64;

    // Constructor mặc định
    public KeyPairModel() {
    }

    // Constructor nhận vào chuỗi Base64 trực tiếp
    public KeyPairModel(String publicKeyBase64, String privateKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
        this.privateKeyBase64 = privateKeyBase64;
    }

    /**
     * Constructor đặc biệt: Nhận vào cặp khóa dạng mã máy của Java
     * và tự động chuyển đổi sang định dạng chuỗi Base64 chuẩn hóa.
     */
    public KeyPairModel(java.security.PublicKey publicKey, java.security.PrivateKey privateKey) {
        if (publicKey != null) {
            this.publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }
        if (privateKey != null) {
            this.privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        }
    }

    // --- Các hàm Getter và Setter ---

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public void setPublicKeyBase64(String publicKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
    }

    public String getPrivateKeyBase64() {
        return privateKeyBase64;
    }

    public void setPrivateKeyBase64(String privateKeyBase64) {
        this.privateKeyBase64 = privateKeyBase64;
    }

    @Override
    public String toString() {
        return "KeyPairModel{" +
                "publicKeyBase64='" + (publicKeyBase64 != null ? publicKeyBase64.substring(0, 20) + "..." : "null") + '\'' +
                ", privateKeyBase64='" + (privateKeyBase64 != null ? "PROTECTED/HIDDEN" : "null") + '\'' +
                '}';
    }
}