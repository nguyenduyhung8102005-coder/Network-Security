package com.anm.digisign.controller;

import com.anm.digisign.crypto.HashService;
import com.anm.digisign.crypto.KeyGeneratorManager;
import com.anm.digisign.crypto.RSAService;
import com.anm.digisign.model.SignRecord;
import com.anm.digisign.model.VerifyRecord;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.Node;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

@Component
public class MainViewController {

    @FXML private TextField txtVerifySigPath;
    @FXML private TextField txtVerifyPubKeyPath;
    @FXML private Label lblKeyStatus;
    @FXML private Label lblVerificationResult;
    @FXML private TextArea txtSignInputText;
    @FXML private TextArea txtVerifyInputText;

    @FXML private TextField txtSignPrivateKeyPath;

    @FXML private Label lblSignedCount;
    @FXML private Label lblVerifiedCount;

    @FXML private TableView<SignRecord> tblSignHistory;
    @FXML private TableColumn<SignRecord, String> colSignTime;
    @FXML private TableColumn<SignRecord, String> colSignDocName;
    @FXML private TableColumn<SignRecord, String> colSignStatus;

    @FXML private TableView<VerifyRecord> tblVerifyHistory;
    @FXML private TableColumn<VerifyRecord, String> colVerifyTime;
    @FXML private TableColumn<VerifyRecord, String> colVerifyDocName;
    @FXML private TableColumn<VerifyRecord, String> colVerifyResult;

    private final ObservableList<SignRecord> signRecords = FXCollections.observableArrayList();
    private final ObservableList<VerifyRecord> verifyRecords = FXCollections.observableArrayList();
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Autowired
    private KeyGeneratorManager keyGeneratorManager;

    @Autowired
    private HashService hashService;

    @Autowired
    private RSAService rsaService;

    private KeyPair currentKeyPair;
    private PrivateKey currentPrivateKey;
    private PublicKey currentPublicKey;

    private int signedCount = 0;
    private int verifiedCount = 0;

    @FXML
    public void initialize() {
        if (colSignTime != null) colSignTime.setCellValueFactory(new PropertyValueFactory<>("time"));
        if (colSignDocName != null) colSignDocName.setCellValueFactory(new PropertyValueFactory<>("docName"));
        if (colSignStatus != null) colSignStatus.setCellValueFactory(new PropertyValueFactory<>("status"));
        if (tblSignHistory != null) tblSignHistory.setItems(signRecords);

        if (colVerifyTime != null) colVerifyTime.setCellValueFactory(new PropertyValueFactory<>("time"));
        if (colVerifyDocName != null) colVerifyDocName.setCellValueFactory(new PropertyValueFactory<>("docName"));
        if (colVerifyResult != null) colVerifyResult.setCellValueFactory(new PropertyValueFactory<>("result"));
        if (tblVerifyHistory != null) tblVerifyHistory.setItems(verifyRecords);
    }

    @FXML
    public void handleGenerateKeys(ActionEvent event) {
        try {
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

    @FXML
    public void handleExportPublicKey(ActionEvent event) {
        if (currentPublicKey == null) {
            showAlert("Thông báo", "Chưa có cặp khóa nào được sinh!", Alert.AlertType.WARNING);
            return;
        }
        try {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Lưu file Public Key");
            fileChooser.setInitialFileName("publicKey.pub");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public Key (*.pub)", "*.pub"));

            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            File fileToSave = fileChooser.showSaveDialog(stage);

            if (fileToSave != null) {
                String publicKeyBase64 = Base64.getEncoder().encodeToString(currentPublicKey.getEncoded());
                Files.write(fileToSave.toPath(), publicKeyBase64.getBytes(StandardCharsets.UTF_8));
                showAlert("Thành công", "Đã xuất file Public Key tại:\n" + fileToSave.getAbsolutePath(), Alert.AlertType.INFORMATION);
            }
        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Lỗi", "Không thể xuất file Public Key: " + e.getMessage(), Alert.AlertType.ERROR);
        }
    }

    @FXML
    public void handleExportPrivateKey(ActionEvent event) {
        if (currentPrivateKey == null) {
            showAlert("Thông báo", "Chưa có cặp khóa nào được sinh!", Alert.AlertType.WARNING);
            return;
        }
        try {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Lưu file Private Key");
            fileChooser.setInitialFileName("privateKey.key");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Private Key (*.key)", "*.key"));

            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            File fileToSave = fileChooser.showSaveDialog(stage);

            if (fileToSave != null) {
                String privateKeyBase64 = Base64.getEncoder().encodeToString(currentPrivateKey.getEncoded());
                Files.write(fileToSave.toPath(), privateKeyBase64.getBytes(StandardCharsets.UTF_8));
                showAlert("Thành công", "Đã xuất file Private Key tại:\n" + fileToSave.getAbsolutePath(), Alert.AlertType.INFORMATION);
            }
        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Lỗi", "Không thể xuất file Private Key: " + e.getMessage(), Alert.AlertType.ERROR);
        }
    }

    @FXML
    public void handleSelectSignPrivateKey(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file Private Key để ký");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Private Key (*.key)", "*.key"));
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            txtSignPrivateKeyPath.setText(selectedFile.getAbsolutePath());
        }
    }

    /**
     * HÀM BỔ TRỢ: Trích xuất nội dung văn bản thô từ .txt, .docx và .pdf
     */
    private String extractTextFromFile(File file) throws IOException {
        String fileName = file.getName().toLowerCase();

        if (fileName.endsWith(".docx")) {
            try (FileInputStream fis = new FileInputStream(file);
                 XWPFDocument document = new XWPFDocument(fis);
                 XWPFWordExtractor extractor = new XWPFWordExtractor(document)) {
                return extractor.getText();
            }
        } else if (fileName.endsWith(".pdf")) {
            try (PDDocument document = Loader.loadPDF(file)) {
                PDFTextStripper pdfStripper = new PDFTextStripper();
                // Truyền biến document vào trong hàm getText()
                return pdfStripper.getText(document);
            }
        } else {
            byte[] bytes = Files.readAllBytes(file.toPath());
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /**
     * CẬP NHẬT: Cho phép tải nội dung từ file mở rộng (.txt, .docx, .pdf)
     */
    @FXML
    public void handleSelectSignDoc(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file văn bản để lấy nội dung");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Tài liệu văn bản (*.txt, *.docx, *.pdf)", "*.txt", "*.docx", "*.pdf"),
                new FileChooser.ExtensionFilter("Tất cả các tệp (*.*)", "*.*")
        );

        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            try {
                String fileContent = extractTextFromFile(selectedFile);
                txtSignInputText.setText(fileContent);
            } catch (Exception e) {
                e.printStackTrace();
                showAlert("Lỗi", "Không thể đọc nội dung file tài liệu: " + e.getMessage(), Alert.AlertType.ERROR);
            }
        }
    }

    @FXML
    public void handleCreateSignature(ActionEvent event) {
        String inputText = txtSignInputText.getText();

        if (inputText == null || inputText.trim().isEmpty()) {
            showAlert("Lỗi", "Vui lòng nhập nội dung văn bản hoặc tải nội dung từ file lên trước khi ký!", Alert.AlertType.ERROR);
            return;
        }

        String timestamp = LocalDateTime.now().format(timeFormatter);
        String displayName = "Văn bản (" + (inputText.length() > 15 ? inputText.substring(0, 15).trim() + "..." : inputText.trim()) + ")";

        String sigFileName = "digital_signature.sig";
        String sigPath = sigFileName;

        String keyPathText = txtSignPrivateKeyPath.getText();
        if (keyPathText != null && !keyPathText.trim().isEmpty()) {
            File keyFile = new File(keyPathText.trim());
            String parentDir = keyFile.getParent();
            if (parentDir != null) {
                sigPath = parentDir + File.separator + sigFileName;
            }
        }

        try {
            PrivateKey privateKeyToUse = getPrivateKeyToUse();
            if (privateKeyToUse == null) {
                showAlert("Lỗi", "Chưa tìm thấy Private Key! Vui lòng chọn file Private Key hoặc chọn 'Sinh cặp khóa mới'.", Alert.AlertType.ERROR);
                return;
            }

            byte[] dataBytes = inputText.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = rsaService.signWithPrivateKey(dataBytes, privateKeyToUse);

            try (FileOutputStream fos = new FileOutputStream(sigPath)) {
                fos.write(signatureBytes);
            }

            showAlert("Thành công", "Đã ký số nội dung văn bản thành công!\nFile chữ ký được lưu tại: " + sigPath, Alert.AlertType.INFORMATION);

            signedCount++;
            if (lblSignedCount != null) lblSignedCount.setText(String.valueOf(signedCount));
            signRecords.add(new SignRecord(timestamp, displayName, "Thành công"));

        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Lỗi", "Có lỗi xảy ra trong quá trình ký số: " + e.getMessage(), Alert.AlertType.ERROR);
            signRecords.add(new SignRecord(timestamp, displayName, "Thất bại: " + e.getMessage()));
        }
    }

    @FXML
    public void handleBatchSign(ActionEvent event) {
        try {
            PrivateKey privateKeyToUse = getPrivateKeyToUse();
            if (privateKeyToUse == null) {
                showAlert("Lỗi", "Chưa tìm thấy Private Key! Vui lòng chọn file Private Key hoặc chọn 'Sinh cặp khóa mới'.", Alert.AlertType.ERROR);
                return;
            }

            DirectoryChooser directoryChooser = new DirectoryChooser();
            directoryChooser.setTitle("Chọn thư mục chứa các văn bản cần ký");
            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            File selectedDir = directoryChooser.showDialog(stage);

            if (selectedDir != null && selectedDir.isDirectory()) {
                File[] files = selectedDir.listFiles((dir, name) ->
                        name.endsWith(".txt") || name.endsWith(".pdf") || name.endsWith(".docx"));

                if (files != null && files.length > 0) {
                    int successCount = 0;
                    String timestamp = LocalDateTime.now().format(timeFormatter);

                    for (File file : files) {
                        try {
                            byte[] fileBytes = Files.readAllBytes(file.toPath());
                            byte[] signatureBytes = rsaService.signWithPrivateKey(fileBytes, privateKeyToUse);

                            String sigPath = file.getAbsolutePath() + ".sig";
                            Files.write(Paths.get(sigPath), signatureBytes);
                            successCount++;

                            signRecords.add(new SignRecord(timestamp, file.getName(), "Thành công (Batch)"));
                        } catch (Exception e) {
                            signRecords.add(new SignRecord(timestamp, file.getName(), "Lỗi lô: " + e.getMessage()));
                        }
                    }
                    showAlert("Hoàn tất", "Đã ký thành công " + successCount + "/" + files.length + " tệp trong thư mục.", Alert.AlertType.INFORMATION);

                    if (successCount > 0) {
                        signedCount += successCount;
                        if (lblSignedCount != null) lblSignedCount.setText(String.valueOf(signedCount));
                    }
                } else {
                    showAlert("Thông báo", "Không tìm thấy tệp văn bản hợp lệ nào trong thư mục đã chọn.", Alert.AlertType.WARNING);
                }
            }
        } catch (Exception e) {
            showAlert("Lỗi", "Lỗi xử lý ký hàng loạt: " + e.getMessage(), Alert.AlertType.ERROR);
        }
    }

    private PrivateKey getPrivateKeyToUse() throws Exception {
        String keyPath = txtSignPrivateKeyPath.getText();

        if (keyPath != null && !keyPath.trim().isEmpty()) {
            byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath.trim()));
            String keyStr = new String(keyBytes, StandardCharsets.UTF_8).trim();

            byte[] decodedKey = Base64.getDecoder().decode(keyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }

        return currentPrivateKey;
    }

    /**
     * CẬP NHẬT: Cho phép tải văn bản đối soát mở rộng (.txt, .docx, .pdf)
     */
    @FXML
    public void handleSelectVerifyDoc(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Chọn file văn bản để đối soát nội dung");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Tài liệu đối soát (*.txt, *.docx, *.pdf)", "*.txt", "*.docx", "*.pdf"),
                new FileChooser.ExtensionFilter("Tất cả các tệp (*.*)", "*.*")
        );

        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        File selectedFile = fileChooser.showOpenDialog(stage);

        if (selectedFile != null) {
            try {
                String fileContent = extractTextFromFile(selectedFile);
                txtVerifyInputText.setText(fileContent);
            } catch (Exception e) {
                e.printStackTrace();
                showAlert("Lỗi", "Không thể đọc tệp tin đối soát: " + e.getMessage(), Alert.AlertType.ERROR);
            }
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

    /**
     * CẬP NHẬT TRIỆT ĐỂ: Đối soát Cipher gỡ lớp mã để phân bổ đúng luồng hiển thị 3 Case
     */
    @FXML
    public void handleVerifyDocument(ActionEvent event) {
        String verifyText = txtVerifyInputText.getText();
        String sigPath = txtVerifySigPath.getText();
        String pubKeyPath = txtVerifyPubKeyPath.getText();

        if (verifyText == null || verifyText.trim().isEmpty() || sigPath.isEmpty() || pubKeyPath.isEmpty()) {
            lblVerificationResult.setText("Kết quả: Thiếu thông tin (Văn bản đối soát / Chữ ký / Public Key)!");
            lblVerificationResult.setStyle("-fx-text-fill: #ea580c; -fx-font-weight: bold;");
            return;
        }

        String timestamp = LocalDateTime.now().format(timeFormatter);
        String displayName = "Văn bản (" + (verifyText.length() > 15 ? verifyText.substring(0, 15).trim() + "..." : verifyText.trim()) + ")";

        verifiedCount++;
        if (lblVerifiedCount != null) lblVerifiedCount.setText(String.valueOf(verifiedCount));

        java.security.PublicKey targetPublicKey = null;

        try {
            lblVerificationResult.setText("Đang tiến hành giám định kiểm tra...");
            lblVerificationResult.setStyle("-fx-text-fill: #0f172a;");

            // =========================================================================
            // CASE 1: KIỂM TRA FILE PUBLIC KEY KHÓA CÔNG KHAI
            // =========================================================================
            try {
                byte[] pubKeyFileBytes = Files.readAllBytes(Paths.get(pubKeyPath));
                String pubKeyStr = new String(pubKeyFileBytes, StandardCharsets.UTF_8).trim();
                byte[] decodedPubKeyBytes = Base64.getDecoder().decode(pubKeyStr);
                targetPublicKey = keyGeneratorManager.getPublicKeyFromBytes(decodedPubKeyBytes);
            } catch (Exception e) {
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! File Public Key của người gửi KHÔNG HỢP LỆ!");
                lblVerificationResult.setStyle("-fx-text-fill: #b91c1c; -fx-font-weight: bold;");
                verifyRecords.add(new VerifyRecord(timestamp, displayName, "Public Key không hợp lệ"));
                return;
            }

            byte[] docBytes = verifyText.getBytes(StandardCharsets.UTF_8);
            byte[] sigBytes = Files.readAllBytes(Paths.get(sigPath));

            // =========================================================================
            // ĐỐI SOÁT CHỮ KÝ VÀ VĂN BẢN (SỬ DỤNG SIGNATURE ENGINE)
            // =========================================================================
            boolean isIdentical = false;
            boolean isSignatureFormatError = false;

            try {
                isIdentical = rsaService.verifyWithPublicKey(docBytes, sigBytes, targetPublicKey);
            } catch (Exception e) {
                isSignatureFormatError = true;
            }

            // 👉 SỬA LỖI GIAO DIỆN: Dùng thuật toán Cipher gỡ Padding kiểm thử để bóc tách luồng lỗi
            if (!isIdentical && !isSignatureFormatError) {
                if (sigBytes.length != 256) {
                    isSignatureFormatError = true;
                } else {
                    try {
                        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA");
                        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, targetPublicKey);
                        cipher.doFinal(sigBytes);
                    } catch (Exception cipherException) {
                        // Bắt trúng lỗi BadPaddingException khi giải mã khối do nạp nhầm file chữ ký của cặp khóa khác
                        isSignatureFormatError = true;
                    }
                }
            }

            // =========================================================================
            // RẼ NHÁNH HIỂN THỊ KẾT QUẢ CHÍNH XÁC LÊN GIAO DIỆN
            // =========================================================================
            if (isSignatureFormatError) {
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! File chữ ký (.sig) KHÔNG HỢP LỆ (hoặc sai cặp khóa)!");
                lblVerificationResult.setStyle("-fx-text-fill: #9a3412; -fx-font-weight: bold;");
                verifyRecords.add(new VerifyRecord(timestamp, displayName, "Chữ ký không hợp lệ"));

            } else if (isIdentical) {
                lblVerificationResult.setText("KẾT QUẢ: Văn bản TOÀN VẸN, chữ ký hoàn toàn HỢP LỆ!");
                lblVerificationResult.setStyle("-fx-text-fill: #15803d; -fx-font-weight: bold;");
                verifyRecords.add(new VerifyRecord(timestamp, displayName, "Toàn vẹn (Hợp lệ)"));

            } else {
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! Nội dung văn bản đã bị SỬA ĐỔI!");
                lblVerificationResult.setStyle("-fx-text-fill: #dc2626; -fx-font-weight: bold;");
                verifyRecords.add(new VerifyRecord(timestamp, displayName, "Văn bản bị sửa đổi"));
            }

        } catch (Exception e) {
            e.printStackTrace();
            lblVerificationResult.setText("Lỗi hệ thống không xác định: " + e.getMessage());
            lblVerificationResult.setStyle("-fx-text-fill: #7f1d1d;");
            verifyRecords.add(new VerifyRecord(timestamp, displayName, "Lỗi hệ thống"));
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