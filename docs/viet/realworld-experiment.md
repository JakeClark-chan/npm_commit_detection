# Thực nghiệm Thực tế: Kiểm thử Áp lực (Stress Testing)

## 1. Mục tiêu
Ngoài các tập dữ liệu tổng hợp, việc xác thực công cụ với **mã độc thực tế** (real-world malware) được tìm thấy ngoài tự nhiên là rất quan trọng. Thử nghiệm này nhằm mục đích kiểm thử áp lực (stress-test) hệ thống đối với một danh sách các kho lưu trữ độc hại đang hoạt động để đánh giá độ bền bỉ và khả năng xử lý các kỹ thuật làm mờ đa dạng mà những kẻ tấn công thực sự sử dụng.

## 2. Phương pháp luận
Chúng tôi đã phát triển một bộ kiểm thử áp lực chuyên dụng (`stress_test_realworld.py`) hoạt động trên một danh sách trực tiếp các kho lưu trữ bị xâm nhập hoặc độc hại (`list-of-realworld-repo.json`).

*   **Phạm vi**: 12 kho lưu trữ độc hại đã biết liên quan đến trộm cắp dữ liệu, đào tiền ảo, và trojan truy cập từ xa (RATs).
*   **Ràng buộc**: Thử nghiệm được giới hạn ở **chỉ Phân tích Tĩnh** để đảm bảo an toàn và tốc độ, mô phỏng kịch bản pre-commit hook nơi việc chạy phân tích động có thể quá chậm.
*   **Đồng thời**: Sử dụng Thread Pool với 8 công nhân (workers) để xử lý nhiều commit cùng lúc.

## 3. Các Phát hiện (Findings)

### 3.1. Phát hiện Thành công
Hệ thống đã xác định thành công các mẫu tinh vi:
*   **Script Cài đặt Bị làm mờ**: Phát hiện các tệp `install.js` chứa tải trọng mã hóa hex được thiết kế để tải xuống các tệp nhị phân hoàn toàn vô hình với regex đơn giản.
*   **Cron Jobs Ẩn**: Xác định các nỗ lực ghi vào `/etc/cron.d` để duy trì sự bền vững (persistence).
*   **Tấn công Chuỗi cung ứng**: Phát hiện các sửa đổi phụ thuộc độc hại trong `package.json`.

### 3.2. Khả năng Suy luận của LLM
Một trong những phát hiện quan trọng nhất là khả năng "kết nối các điểm dữ liệu" của LLM.
> *Ví dụ*: Trong một repo, mã đã chia nhỏ một URL độc hại thành ba biến chuỗi riêng biệt và chỉ nối chúng lại tại thời điểm gọi `fetch`. LLM Phân tích Tĩnh đã tái tạo chính xác chuỗi và gắn cờ miền đó là máy chủ C2.

## 4. Thách thức được Xác định
*   **Giới hạn Token**: Các tệp minified cực lớn đôi khi vượt quá cửa sổ ngữ cảnh của LLM. Chúng tôi đã triển khai "Chiến lược Phân mảnh" (Chunking Strategy) để giảm thiểu điều này, nhưng đôi khi nó làm phá vỡ ngữ cảnh ngữ nghĩa.
*   **Script Mơ hồ**: Một số hành vi "độc hại" (ví dụ: báo cáo đo lường từ xa) trông giống hệt với mã phân tích hợp pháp.

## 5. Tóm tắt
Cuộc kiểm thử áp lực thực tế đã xác nhận rằng hệ thống đã sẵn sàng cho sản phẩm để xác định các mối đe dọa có tác động cao. Nó chứng minh rằng ngay cả khi không có phân tích động, Phân tích Tĩnh nâng cao (LLM + Giải mã) vẫn rất hiệu quả trong việc bắt kịp các xu hướng mã độc hiện tại.
