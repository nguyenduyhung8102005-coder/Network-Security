package com.anm.digisign.crypto;

import com.anm.digisign.model.VerificationResult;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
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
     * QUY TRÌNH KÝ SỐ RSA CHUẨN:
     * Sử dụng Signature Engine (SHA256withRSA) ký trực tiếp trên dữ liệu tệp tin.
     * Thuật toán tự động băm dữ liệu và mã hóa bảo mật bên dưới tầng core của RSAService.
     */
    public byte[] signDocument(byte[] fileData, PrivateKey privateKey) throws Exception {
        // 👉 THAY ĐỔI: Sử dụng thẳng cơ chế ký Signature mã hóa bảo mật của RSAService
        return rsaService.signWithPrivateKey(fileData, privateKey);
    }

    /**
     * QUY TRÌNH XÁC THỰC & PHÂN TÁCH LỖI GIÁM ĐỊNH CHI TIẾT:
     * 1. Kiểm tra tính toàn vẹn của tệp tin đối soát và tệp chữ ký thông qua Signature Engine.
     * 2. Phân tách rõ ràng trường hợp Chữ ký không hợp lệ và Văn bản bị chỉnh sửa dữ liệu gốc.
     */
    public VerificationResult verifyDocument(byte[] currentFileData, byte[] signatureBytes, PublicKey publicKey) {
        try {
            // 👉 THAY ĐỔI: Gọi hàm verify từ RSAService sử dụng Signature Engine chuẩn RSA
            boolean isIntegrityMaintained = rsaService.verifyWithPublicKey(currentFileData, signatureBytes, publicKey);

            if (isIntegrityMaintained) {
                return new VerificationResult(true, "Xác thực thành công: Nội dung văn bản nguyên vẹn.");
            } else {
                // Rơi vào đây tức là định dạng chữ ký số chuẩn, giải mã thành công nhưng nội dung văn bản đã bị sửa đổi trái phép
                return new VerificationResult(false, "CẢNH BÁO: Nội dung văn bản đã bị SỬA ĐỔI!");
            }

        } catch (Exception e) {
            // Rơi vào khối catch khi Signature Engine quăng lỗi cấu trúc (ví dụ: file .sig lỗi định dạng dữ liệu byte, sai cặp khóa thuật toán)
            return new VerificationResult(false, "CẢNH BÁO: File chữ ký (.sig) KHÔNG HỢP LỆ (hoặc sai cặp khóa)!");
        }
    }

    public void signPDFDocument(File inputFile, File outputFile, PrivateKey privateKey) throws Exception {
        // 👉 ĐÃ SỬA LỖI: Sử dụng Loader.loadPDF(File) thay thế cho PDDocument.load() đã bị loại bỏ ở bản 3.x
        try (PDDocument document = Loader.loadPDF(inputFile)) {
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