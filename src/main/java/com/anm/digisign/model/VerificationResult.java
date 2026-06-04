package com.anm.digisign.model;

/**
 * Model chứa kết quả kiểm tra tính toàn vẹn và xác thực của văn bản.
 */
public class VerificationResult {
    private boolean isValid;  // true: văn bản nguyên vẹn, false: đã bị sửa đổi/chữ ký giả
    private String message;   // Thông báo chi tiết (v dụ: lý do thất bại hoặc xác thực thành công)

    // Constructor mặc định (Cần thiết cho việc serialize/deserialize JSON của Spring Boot)
    public VerificationResult() {
    }

    // Constructor có tham số
    public VerificationResult(boolean isValid, String message) {
        this.isValid = isValid;
        this.message = message;
    }

    // --- Các hàm Getter và Setter ---

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "VerificationResult{" +
                "isValid=" + isValid +
                ", message='" + message + '\'' +
                '}';
    }
}