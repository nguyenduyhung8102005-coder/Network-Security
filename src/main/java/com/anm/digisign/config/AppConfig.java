package com.anm.digisign.config;

import com.anm.digisign.crypto.HashService;
import com.anm.digisign.crypto.RSAService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    // Đọc các tham số cấu hình bảo mật an ninh mạng từ file application.properties
    @Value("${cryptography.rsa.key-size:2048}")
    private int rsaKeySize;

    @Value("${cryptography.rsa.transformation:RSA/ECB/PKCS1Padding}")
    private String rsaTransformation;

    @Value("${cryptography.hash.algorithm:SHA-256}")
    private String hashAlgorithm;

    /**
     * Khởi tạo HashService dưới dạng một Spring Bean dùng chung cho toàn hệ thống.
     * Tự động cấu hình thuật toán băm (mặc định là SHA-256).
     */
    @Bean
    public HashService hashService() {
        return new HashService(this.hashAlgorithm);
    }

    /**
     * Khởi tạo RSAService dưới dạng một Spring Bean dùng chung cho toàn hệ thống.
     * Cấu hình chế độ mã hóa/giải mã (mặc định là RSA/ECB/PKCS1Padding).
     */
    @Bean
    public RSAService rsaService() {
        return new RSAService();
    }

    // --- Các hàm Getter để cung cấp tham số cho KeyGenerator hoặc các logic khác khi cần ---

    public int getRsaKeySize() {
        return rsaKeySize;
    }

    public String getRsaTransformation() {
        return rsaTransformation;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }
}