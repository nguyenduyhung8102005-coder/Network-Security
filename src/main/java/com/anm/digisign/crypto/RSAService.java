package com.anm.digisign.crypto;

import org.springframework.stereotype.Service;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

@Service
public class RSAService {

    /**
     * 🔥 KÝ SỐ RSA CHUẨN: Sử dụng Signature Engine với thuật toán SHA256withRSA
     * Tự động băm SHA-256 nội dung văn bản thô bên dưới tầng core và tiến hành ký bằng Private Key.
     * Giải quyết triệt để vấn đề giới hạn độ dài khối dữ liệu của Cipher RSA thô.
     *
     * @param docBytes   Mảng byte của nội dung văn bản thô cần ký số
     * @param privateKey Khóa bí mật (Private Key) dùng để ký
     * @return Mảng byte của chữ ký số (.sig) chuẩn hóa
     * @throws Exception Các ngoại lệ liên quan đến cấu trúc khóa hoặc thuật toán mật mã
     */
    public byte[] signWithPrivateKey(byte[] docBytes, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(docBytes);
        return sig.sign();
    }

    /**
     * 🔥 XÁC THỰC CHỮ KÝ SỐ RSA CHUẨN: Sử dụng thuật toán SHA256withRSA
     * Tiến hành nạp khóa công khai, nạp văn bản thô đối soát và thẩm định tệp tin chữ ký .sig.
     *
     * @param docBytes  Mảng byte của văn bản thô cần đối soát hiện tại trên UI
     * @param sigBytes  Mảng byte của tệp chữ ký số (.sig) nạp vào hệ thống
     * @param publicKey Khóa công khai (Public Key) của người gửi dùng để xác thực
     * @return true nếu văn bản toàn vẹn (khớp hoàn toàn); false nếu văn bản đã bị sửa đổi
     * @throws Exception Quăng ngoại lệ cấu trúc nếu file .sig bị hỏng hoặc sai định dạng byte
     */
    public boolean verifyWithPublicKey(byte[] docBytes, byte[] sigBytes, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(docBytes);
        return sig.verify(sigBytes); // Trả về true/false hoặc quăng lỗi cấu trúc byte chữ ký
    }
}