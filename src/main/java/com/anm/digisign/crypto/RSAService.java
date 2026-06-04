package com.anm.digisign.crypto;

import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
public class RSAService {

    // Định dạng Cipher transformation chuẩn hóa của hệ thống
    private final String transformation = "RSA/ECB/PKCS1Padding";

    /**
     * KÝ SỐ: Mã hóa mảng byte dữ liệu (Chuỗi băm SHA-256) bằng Private Key
     */
    public byte[] encryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        // Chế độ ENCRYPT_MODE phối hợp với khóa bí mật để tạo Signature
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * XÁC THỰC: Giải mã chữ ký số (.sig) bằng Public Key để lấy lại chuỗi băm gốc
     */
    public byte[] decryptWithPublicKey(byte[] encryptedData, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        // 🔥 ĐẢM BẢO CHÍNH XÁC: Phải là DECRYPT_MODE và truyền vào publicKey
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }
}