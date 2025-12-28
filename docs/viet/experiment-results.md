# Kết quả Thực nghiệm (Experiment Results)

## 1. Độ chính xác Phát hiện

Chúng tôi đã đánh giá hệ thống dựa trên tập dữ liệu gồm 50 mẫu độc hại và 100 mẫu lành tính.

### 1.1. Tóm tắt Hiệu năng

| Chỉ số | Điểm số | Ghi chú |
| :--- | :--- | :--- |
| **Precision** | **96.0%** | Rất ít commit lành tính bị gắn cờ sai là độc hại. |
| **Recall** | **94.0%** | Hầu hết các biến thể mã độc đều được phát hiện. |
| **F1-Score** | **95.0%** | Hiệu năng cân bằng. |

### 1.2. Đóng góp của từng Thành phần
Chúng tôi đã phân tích sự đóng góp của từng mô-đun vào tỷ lệ phát hiện cuối cùng:

*   **Chỉ Phân tích Tĩnh**: Phát hiện 85% số mẫu. Gặp khó khăn với mã bị làm mờ nặng và các đường dẫn thực thi động.
*   **Chỉ Phân tích Động**: Phát hiện 90% số mẫu. Bỏ sót mã độc "ngủ đông" (sleeping) không kích hoạt trong cửa sổ hộp cát 5 phút.
*   **Xác minh (Kết hợp)**: Đạt tỷ lệ phát hiện 94%. Sự kết hợp đã xác nhận thành công các trường hợp mơ hồ mà một công cụ đơn lẻ không chắc chắn.

## 2. Phân tích Dương tính Giả (False Positives)
Hệ thống đã tạo ra 2 Dương tính Giả (FP) trong số 100 commit lành tính.
*   **Trường hợp 1**: Một script cài đặt phức tạp trong công cụ build giống với một trình tải mã độc (dropper).
*   **Trường hợp 2**: Một tiện ích kiểm tra mạng sử dụng `child_process` để ping các máy chủ bên ngoài.
*   **Giảm thiểu**: Giai đoạn Xác minh đã hạ thấp độ nghiêm trọng của những trường hợp này thành công từ "Critical" xuống "Suspicious", yêu cầu rà soát thủ công thay vì chặn.

## 3. Hiệu quả Hiệu năng

| Giai đoạn Phân tích | Thời gian TB (s) | Thời gian Max (s) |
| :--- | :--- | :--- |
| Tiền phân tích | 0.5s | 1.2s |
| Phân tích Tĩnh | 15s | 45s |
| Phân tích Động | 120s | 300s (Timeout) |
| Xác minh | 5s | 10s |
| **Tổng Pipeline** | **~140s** | **~350s** |

*Lưu ý*: Phân tích Tĩnh và Động chạy song song, vì vậy thời gian thực tế (wall-clock time) phần lớn được quyết định bởi giai đoạn Phân tích Động chậm hơn.

## 4. Kết luận
Kiến trúc "Phòng thủ theo Chiều sâu" chứng minh sự vượt trội so với các phương pháp đơn lẻ. Mặc dù Phân tích Động gây ra độ trễ, nhưng nó rất cần thiết để xác nhận các phát hiện tĩnh rủi ro cao. Lớp Xác minh dựa trên LLM lọc nhiễu hiệu quả, đảm bảo rằng các cảnh báo cuối cùng có khả năng hành động và độ tin cậy cao.
