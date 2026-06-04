package com.anm.digisign.crypto;

import com.anm.digisign.model.VerificationResult;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;

@Service
public class SignatureEngine {

    private final HashService hashService;
    private final RSAService rsaService;

    @Autowired
    public SignatureEngine(HashService hashService, RSAService rsaService) {
        this.hashService = hashService;
        this.rsaService = rsaService;
    }

    /**
     * QUY TRÌNH KÝ SỐ:
     * 1. Băm văn bản (Sử dụng thuật toán trong AppConfig)
     * 2. Mã hóa mã băm bằng Private Key (RSA)
     */
    public byte[] signDocument(byte[] fileData, PrivateKey privateKey) throws Exception {
        // Bước 1: Tạo mã băm (Digest)
        byte[] hashValue = hashService.computeHash(fileData);

        // Bước 2: Ký lên mã băm đó
        return rsaService.encryptWithPrivateKey(hashValue, privateKey);
    }

    /**
     * QUY TRÌNH XÁC THỰC & KIỂM TRA SỬA ĐỔI:
     * 1. Giải mã chữ ký bằng Public Key để lấy Hash gốc (A)
     * 2. Băm lại văn bản hiện tại để lấy Hash hiện tại (B)
     * 3. So sánh A và B. Nếu khác nhau => Văn bản đã bị sửa đổi.
     */
    public VerificationResult verifyDocument(byte[] currentFileData, byte[] signatureBytes, PublicKey publicKey) {
        try {
            // Bước 1: Giải mã chữ ký cũ
            byte[] originalHash = rsaService.decryptWithPublicKey(signatureBytes, publicKey);

            // Bước 2: Băm dữ liệu văn bản hiện tại
            byte[] currentHash = hashService.computeHash(currentFileData);

            // Bước 3: Đối soát tính toàn vẹn
            boolean isIntegrityMaintained = MessageDigest.isEqual(originalHash, currentHash);

            if (isIntegrityMaintained) {
                return new VerificationResult(true, "Xác thực thành công: Nội dung văn bản nguyên vẹn.");
            } else {
                return new VerificationResult(false, "CẢNH BÁO: Văn bản đã bị sửa đổi hoặc chữ ký không hợp lệ!");
            }

        } catch (Exception e) {
            return new VerificationResult(false, "Lỗi xác thực: " + e.getMessage());
        }
    }

    public void signPDFDocument(File inputFile, File outputFile, PrivateKey privateKey) throws Exception {
        try (PDDocument document = PDDocument.load(inputFile)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Người ký: Hệ thống An ninh mạng");
            signature.setReason("Xác thực tính toàn vẹn của văn bản");
            signature.setSignDate(Calendar.getInstance());

            // Đăng ký chữ ký vào PDF (cần implement SignatureInterface tích hợp RSAService của bạn)
            // document.addSignature(signature, new CustomSignatureInterface(privateKey));

            document.saveIncremental(new FileOutputStream(outputFile));
        }
    }
}