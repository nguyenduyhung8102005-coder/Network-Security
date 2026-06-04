package com.anm.digisign.controller;

import com.anm.digisign.crypto.HashService;
import com.anm.digisign.crypto.KeyGeneratorManager;
import com.anm.digisign.crypto.RSAService;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.Node;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Component
public class MainViewController {

    @FXML private TextField txtSignDocPath;
    @FXML private TextField txtVerifyDocPath;
    @FXML private TextField txtVerifySigPath;
    @FXML private TextField txtVerifyPubKeyPath;
    @FXML private Label lblKeyStatus;
    @FXML private Label lblVerificationResult;

    // --- TẬP HỢP TẤT CẢ BEAN SERVICE LÊN ĐẦU CLASS ---
    @Autowired
    private KeyGeneratorManager keyGeneratorManager;

    @Autowired
    private HashService hashService;

    @Autowired
    private RSAService rsaService;

    // --- BIẾN TRẠNG THÁI TOÀN CỤC ---
    private KeyPair currentKeyPair;
    private PrivateKey currentPrivateKey;
    private PublicKey currentPublicKey;

    /**
     * 1. Xử lý sự kiện bấm nút "Sinh cặp khóa mới"
     */
    @FXML
    public void handleGenerateKeys(ActionEvent event) {
        try {
            // 🔥 ĐÃ SỬA: Sử dụng trực tiếp manager được Spring quản lý thay vì tạo local
            currentKeyPair = keyGeneratorManager.generateKeyPair();

            this.currentPrivateKey = currentKeyPair.getPrivate();
            this.currentPublicKey = currentKeyPair.getPublic();

            if (lblKeyStatus != null) {
                lblKeyStatus.setText("Trạng thái khóa: Đã khởi tạo cặp khóa thành công từ Manager!");
            }
            System.out.println("Sinh cặp khóa RSA thành công.");
        } catch (Exception e) {
            if (lblKeyStatus != null) {
                lblKeyStatus.setText("Lỗi khi sinh khóa: " + e.getMessage());
            }
            e.printStackTrace();
        }
    }

    /**
     * 2. Xử lý sự kiện bấm nút "Xuất Public Key"
     */
    @FXML
    public void handleExportPublicKey(ActionEvent event) {
        if (currentPublicKey == null) {
            showAlert("Thông báo", "Chưa có cặp khóa nào được sinh!", Alert.AlertType.WARNING);
            return;
        }
        try {
            // Gợi ý: Lưu thẳng file .pub ra máy người dùng để Khối 3 dùng luôn thay vì chỉ log console
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Lưu file Public Key");
            fileChooser.setInitialFileName("publicKey.pub");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public Key (*.pub)", "*.pub"));

            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            File fileToSave = fileChooser.showSaveDialog(stage);

            if (fileToSave != null) {
                // Xuất file dạng nhị phân mã hóa chuẩn X.509 dể tí nữa dễ đọc lại
                Files.write(fileToSave.toPath(), currentPublicKey.getEncoded());
                showAlert("Thành công", "Đã xuất file Public Key tại:\n" + fileToSave.getAbsolutePath(), Alert.AlertType.INFORMATION);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 3. Xử lý sự kiện bấm nút "Xuất Private Key"
     */
    @FXML
    public void handleExportPrivateKey(ActionEvent event) {
        if (currentPrivateKey == null) {
            showAlert("Thông báo", "Chưa có cặp khóa nào được sinh!", Alert.AlertType.WARNING);
            return;
        }
        try {
            String privateKeyBase64 = Base64.getEncoder().encodeToString(currentPrivateKey.getEncoded());
            System.out.println("--- PRIVATE KEY (Base64) ---");
            System.out.println(privateKeyBase64);
            // Có thể bổ sung logic lưu file .pri tương tự như Public Key khi cần bảo mật
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- KHỐI 2: KÝ SỐ VĂN BẢN ---

    @FXML
    public void handleSelectSignDoc(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file văn bản cần ký số");
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            txtSignDocPath.setText(selectedFile.getAbsolutePath());
        }
    }

    @FXML
    public void handleCreateSignature(ActionEvent event) {
        String docPath = txtSignDocPath.getText();

        if (docPath == null || docPath.isEmpty()) {
            showAlert("Lỗi", "Vui lòng chọn file trước khi thực hiện ký!", Alert.AlertType.ERROR);
            return;
        }

        if (currentPrivateKey == null) {
            showAlert("Lỗi", "Chưa tìm thấy Private Key! Vui lòng sinh cặp khóa trước.", Alert.AlertType.ERROR);
            return;
        }

        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get(docPath));
            byte[] hashBytes = hashService.computeHash(fileBytes);
            byte[] signatureBytes = rsaService.encryptWithPrivateKey(hashBytes, currentPrivateKey);

            String sigPath = docPath + ".sig";
            try (FileOutputStream fos = new FileOutputStream(sigPath)) {
                fos.write(signatureBytes);
            }

            System.out.println("Ký số thành công! File chữ ký lưu tại: " + sigPath);
            showAlert("Thành công", "Đã ký số thành công!\nFile chữ ký: " + sigPath, Alert.AlertType.INFORMATION);

        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Lỗi", "Có lỗi xảy ra trong quá trình ký số: " + e.getMessage(), Alert.AlertType.ERROR);
        }
    }

    // --- KHỐI 3: XÁC THỰC & KIỂM TRA SỬA ĐỔI VĂN BẢN ---

    @FXML
    public void handleSelectVerifyDoc(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file văn bản hiện tại để đối soát");
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            txtVerifyDocPath.setText(selectedFile.getAbsolutePath());
        }
    }

    @FXML
    public void handleSelectVerifySig(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file chữ ký .sig tương ứng");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Signature Files (*.sig)", "*.sig"));
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            txtVerifySigPath.setText(selectedFile.getAbsolutePath());
        }
    }

    @FXML
    public void handleSelectVerifyPubKey(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file Public Key (.pub)");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public Key Files (*.pub)", "*.pub"));
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            txtVerifyPubKeyPath.setText(selectedFile.getAbsolutePath());
        }
    }

    @FXML
    public void handleVerifyDocument(ActionEvent event) {
        if (txtVerifyDocPath.getText().isEmpty() ||
                txtVerifySigPath.getText().isEmpty() ||
                txtVerifyPubKeyPath.getText().isEmpty()) {
            lblVerificationResult.setText("Kết quả: Thiếu thông tin file đối soát!");
            return;
        }

        try {
            System.out.println("Bắt đầu đối soát tính toàn vẹn dữ liệu...");
            lblVerificationResult.setText("Đang kiểm tra...");

            // 1. Đọc dữ liệu từ các trường dẫn file
            byte[] docBytes = Files.readAllBytes(Paths.get(txtVerifyDocPath.getText()));
            byte[] sigBytes = Files.readAllBytes(Paths.get(txtVerifySigPath.getText()));
            byte[] pubKeyBytes = Files.readAllBytes(Paths.get(txtVerifyPubKeyPath.getText()));

            // 2. Khôi phục PublicKey từ mảng byte
            PublicKey publicKey = keyGeneratorManager.getPublicKeyFromBytes(pubKeyBytes);

            // 3. Băm file văn bản hiện tại (Kết quả SHA-256 luôn cố định là 32 bytes)
            byte[] currentHash = hashService.computeHash(docBytes);

            // 🔥 SỬA TẠI ĐÂY: Tham số đầu tiên phải là mảng byte của CHỮ KÝ (sigBytes), KHÔNG ĐƯỢC truyền docBytes
            byte[] decryptedHash = rsaService.decryptWithPublicKey(sigBytes, publicKey);

            // 4. So sánh mã băm vừa giải mã từ chữ ký với mã băm của văn bản hiện tại
            boolean isIdentical = java.util.Arrays.equals(currentHash, decryptedHash);

            if (isIdentical) {
                lblVerificationResult.setText("KẾT QUẢ: Văn bản TOÀN VẸN, chữ ký HỢP LỆ!");
                lblVerificationResult.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");
            } else {
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! Văn bản đã bị SỬA ĐỔI hoặc chữ ký SAI!");
                lblVerificationResult.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
            }

        } catch (Exception e) {
            e.printStackTrace();
            lblVerificationResult.setText("Lỗi xác thực: " + e.getMessage());
            lblVerificationResult.setStyle("-fx-text-fill: orange;");
        }
    }

    private void showAlert(String title, String content, Alert.AlertType type) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }
}