package com.anm.digisign;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class DigisignApplication extends Application {

	private static ConfigurableApplicationContext springContext;

	/**
	 * Hàm init() thuộc vòng đời JavaFX, tự động chạy trước hàm start().
	 * Chúng ta khởi chạy Spring Boot tại đây để đảm bảo context luôn sẵn sàng.
	 */
	@Override
	public void init() throws Exception {
		String[] args = getParameters().getRaw().toArray(new String[0]);
		springContext = SpringApplication.run(DigisignApplication.class, args);
	}

	@Override
	public void start(Stage primaryStage) throws Exception {
		// Nạp file cấu trúc giao diện FXML từ tài nguyên hệ thống
		FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("/view/MainView.fxml"));

		// Sử dụng lớp quản lý tĩnh để lấy Bean từ Spring Container, xóa bỏ hoàn toàn lỗi gạch đỏ inspection
		fxmlLoader.setControllerFactory(DigisignApplication.springContext::getBean);

		Parent root = fxmlLoader.load();

		// Cấu hình giao diện cửa sổ ứng dụng
		primaryStage.setTitle("Hệ thống Xác thực Chữ ký số RSA");
		primaryStage.setScene(new Scene(root, 1050, 720));
		primaryStage.setResizable(false);
		primaryStage.show();
	}

	@Override
	public void stop() throws Exception {
		// Giải phóng tài nguyên Spring ngầm khi tắt ứng dụng giao diện
		if (DigisignApplication.springContext != null) {
			DigisignApplication.springContext.close();
		}
		super.stop();
	}

	public static void main(String[] args) {
		// Gọi thẳng luồng kích hoạt của JavaFX (hệ thống sẽ tự gọi sang init() và start())
		Application.launch(DigisignApplication.class, args);
	}
}