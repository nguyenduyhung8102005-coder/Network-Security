package com.anm.digisign.controller;

import com.anm.digisign.crypto.HashService;
import com.anm.digisign.crypto.KeyGeneratorManager;
import com.anm.digisign.crypto.RSAService;
// --- IMPORT HAI MODEL ĐÃ TÁCH RIÊNG ---
import com.anm.digisign.model.SignRecord;
import com.anm.digisign.model.VerifyRecord;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

@Component
public class MainViewController {

    @FXML private TextField txtSignDocPath;
    @FXML private TextField txtVerifyDocPath;
    @FXML private TextField txtVerifySigPath;
    @FXML private TextField txtVerifyPubKeyPath;
    @FXML private Label lblKeyStatus;
    @FXML private Label lblVerificationResult;

    // --- KHAI BÁO THÊM LABEL ĐỂ HIỂN THỊ SỐ LƯỢNG LÊN TAB TỔNG QUAN ---
    @FXML private Label lblSignedCount;
    @FXML private Label lblVerifiedCount;

    // --- KHAI BÁO CÁC CONTROL CHO TAB LỊCH SỬ ---
    @FXML private TableView<SignRecord> tblSignHistory;
    @FXML private TableColumn<SignRecord, String> colSignTime;
    @FXML private TableColumn<SignRecord, String> colSignDocName;
    @FXML private TableColumn<SignRecord, String> colSignStatus;

    @FXML private TableView<VerifyRecord> tblVerifyHistory;
    @FXML private TableColumn<VerifyRecord, String> colVerifyTime;
    @FXML private TableColumn<VerifyRecord, String> colVerifyDocName;
    @FXML private TableColumn<VerifyRecord, String> colVerifyResult;

    // Danh sách lưu trữ dữ liệu để hiển thị lên TableView
    private final ObservableList<SignRecord> signRecords = FXCollections.observableArrayList();
    private final ObservableList<VerifyRecord> verifyRecords = FXCollections.observableArrayList();
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

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

    // --- CÁC BIẾN ĐẾM SỐ LƯỢNG VĂN BẢN ---
    private int signedCount = 0;
    private int verifiedCount = 0;

    /**
     * Phương thức khởi tạo cấu hình TableView của JavaFX
     */
    @FXML
    public void initialize() {
        // Cấu hình các cột cho bảng Lịch sử ký số
        if (colSignTime != null) colSignTime.setCellValueFactory(new PropertyValueFactory<>("time"));
        if (colSignDocName != null) colSignDocName.setCellValueFactory(new PropertyValueFactory<>("docName"));
        if (colSignStatus != null) colSignStatus.setCellValueFactory(new PropertyValueFactory<>("status"));
        if (tblSignHistory != null) tblSignHistory.setItems(signRecords);

        // Cấu hình các cột cho bảng Lịch sử xác thực
        if (colVerifyTime != null) colVerifyTime.setCellValueFactory(new PropertyValueFactory<>("time"));
        if (colVerifyDocName != null) colVerifyDocName.setCellValueFactory(new PropertyValueFactory<>("docName"));
        if (colVerifyResult != null) colVerifyResult.setCellValueFactory(new PropertyValueFactory<>("result"));
        if (tblVerifyHistory != null) tblVerifyHistory.setItems(verifyRecords);
    }

    /**
     * 1. Xử lý sự kiện bấm nút "Sinh cặp khóa mới"
     */
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
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Lưu file Public Key");
            fileChooser.setInitialFileName("publicKey.pub");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Public Key (*.pub)", "*.pub"));

            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            File fileToSave = fileChooser.showSaveDialog(stage);

            if (fileToSave != null) {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // --- KHỐI 2: KÝ SỐ VĂN BẢN (ĐƠN & HÀNG LOẠT) ---

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

        File file = new File(docPath);
        String timestamp = LocalDateTime.now().format(timeFormatter);

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

            // 🔥 LOGIC: Tăng số lượng văn bản đã ký đơn thành công
            signedCount++;
            if (lblSignedCount != null) {
                lblSignedCount.setText(String.valueOf(signedCount));
            }

            // 🔥 LOGIC: Ghi nhận lịch sử ký đơn thành công
            signRecords.add(new SignRecord(timestamp, file.getName(), "Thành công (Đơn)"));

        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Lỗi", "Có lỗi xảy ra trong quá trình ký số: " + e.getMessage(), Alert.AlertType.ERROR);

            // 🔥 LOGIC: Ghi nhận lịch sử ký đơn thất bại
            signRecords.add(new SignRecord(timestamp, file.getName(), "Thất bại: " + e.getMessage()));
        }
    }

    /**
     * TÍNH NĂNG MỚI: Xử lý ký số hàng loạt (Batch Signing)
     */
    @FXML
    public void handleBatchSign(ActionEvent event) {
        if (currentPrivateKey == null) {
            showAlert("Lỗi", "Chưa có Private Key! Vui lòng sinh cặp khóa trước.", Alert.AlertType.ERROR);
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
                        byte[] hashBytes = hashService.computeHash(fileBytes);
                        byte[] signatureBytes = rsaService.encryptWithPrivateKey(hashBytes, currentPrivateKey);

                        String sigPath = file.getAbsolutePath() + ".sig";
                        Files.write(Paths.get(sigPath), signatureBytes);
                        successCount++;

                        // 🔥 LOGIC: Ghi từng file trong lô vào bảng lịch sử
                        signRecords.add(new SignRecord(timestamp, file.getName(), "Thành công (Batch)"));
                    } catch (Exception e) {
                        System.err.println("Lỗi khi ký file: " + file.getName() + " - " + e.getMessage());
                        // 🔥 LOGIC: Ghi nhận lỗi file cụ thể vào bảng lịch sử
                        signRecords.add(new SignRecord(timestamp, file.getName(), "Lỗi lô: " + e.getMessage()));
                    }
                }
                showAlert("Hoàn tất", "Đã ký thành công " + successCount + "/" + files.length + " tệp trong thư mục.", Alert.AlertType.INFORMATION);

                if (successCount > 0) {
                    signedCount += successCount;
                    if (lblSignedCount != null) {
                        lblSignedCount.setText(String.valueOf(signedCount));
                    }
                }
            } else {
                showAlert("Thông báo", "Không tìm thấy tệp văn bản hợp lệ nào trong thư mục đã chọn.", Alert.AlertType.WARNING);
            }
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

        String docPath = txtVerifyDocPath.getText();
        File file = new File(docPath);
        String timestamp = LocalDateTime.now().format(timeFormatter);

        try {
            System.out.println("Bắt đầu đối soát tính toàn vẹn dữ liệu...");
            lblVerificationResult.setText("Đang kiểm tra...");

            byte[] docBytes = Files.readAllBytes(Paths.get(docPath));
            byte[] sigBytes = Files.readAllBytes(Paths.get(txtVerifySigPath.getText()));
            byte[] pubKeyBytes = Files.readAllBytes(Paths.get(txtVerifyPubKeyPath.getText()));

            PublicKey publicKey = keyGeneratorManager.getPublicKeyFromBytes(pubKeyBytes);
            byte[] currentHash = hashService.computeHash(docBytes);

            byte[] decryptedHash;
            try {
                decryptedHash = rsaService.decryptWithPublicKey(sigBytes, publicKey);
            } catch (Exception signatureException) {
                System.err.println("Lỗi giải mã chữ ký: " + signatureException.getMessage());
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! Chữ ký KHÔNG HỢP LỆ (hoặc sai khóa)!");
                lblVerificationResult.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");

                // 🔥 LOGIC: Ghi log xác thực thất bại do lỗi chữ ký
                verifyRecords.add(new VerifyRecord(timestamp, file.getName(), "Chữ ký KHÔNG HỢP LỆ"));
                return;
            }

            boolean isIdentical = java.util.Arrays.equals(currentHash, decryptedHash);

            verifiedCount++;
            if (lblVerifiedCount != null) {
                lblVerifiedCount.setText(String.valueOf(verifiedCount));
            }

            if (isIdentical) {
                lblVerificationResult.setText("KẾT QUẢ: Văn bản TOÀN VẸN, chữ ký HỢP LỆ!");
                lblVerificationResult.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");

                // 🔥 LOGIC: Ghi log tài liệu Toàn vẹn
                verifyRecords.add(new VerifyRecord(timestamp, file.getName(), "Toàn vẹn (Hợp lệ)"));
            } else {
                lblVerificationResult.setText("KẾT QUẢ: CẢNH BÁO! Văn bản đã bị SỬA ĐỔI!");
                lblVerificationResult.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");

                // 🔥 LOGIC: Ghi log phát hiện tài liệu bị thay đổi
                verifyRecords.add(new VerifyRecord(timestamp, file.getName(), "CẢNH BÁO: Bị sửa đổi"));
            }

        } catch (Exception e) {
            e.printStackTrace();
            lblVerificationResult.setText("Lỗi hệ thống hoặc đọc file: " + e.getMessage());
            lblVerificationResult.setStyle("-fx-text-fill: orange;");

            // 🔥 LOGIC: Ghi nhận lỗi hệ thống vào lịch sử
            verifyRecords.add(new VerifyRecord(timestamp, file.getName(), "Lỗi đọc file/Hệ thống"));
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