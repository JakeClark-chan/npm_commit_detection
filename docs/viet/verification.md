# Giai đoạn Xác minh (Verification)

## 1. Tổng quan
**Giai đoạn Xác minh** là cơ chế ra quyết định cuối cùng của đường ống. Nó tương quan các phát hiện từ các mô-đun phân tích khác nhau (Tĩnh, Động, Snyk) để loại bỏ các dương tính giả và xác nhận các dương tính thật. Bằng cách giảm thiểu nhiễu vốn có trong các công cụ riêng lẻ, nó cung cấp một phán quyết có độ tin cậy cao.

## 2. Phương pháp luận

Logic xác minh (`llm/verification.py`) sử dụng **Thuật toán Tương quan Đa giai đoạn**:

### 2.1. Chuẩn hóa (Normalization)
Đầu tiên, đầu ra từ tất cả các công cụ được ánh xạ tới lược đồ `NormalizedFinding` thống nhất:
*   `category`: ví dụ: `code_injection`, `network_access`.
*   `severity`: CRITICAL, HIGH, MEDIUM, LOW.
*   `evidence`: Đoạn mã (Tĩnh) hoặc Lời gọi hệ thống/Log (Động).
*   `location`: Đường dẫn tệp (Tĩnh) hoặc Tiến trình/IP (Động).

### 2.2. Đối sánh Chéo Phân tích (Cross-Analysis Matching)
Chúng tôi sử dụng LLM để đối sánh ngữ nghĩa các phát hiện giữa các miền.
Gọi $S$ là các phát hiện tĩnh và $D$ là các phát hiện động. Một khớp nối $M(s, d)$ được thiết lập nếu:
$$
\text{SemanticSimilarity}(s_{desc}, d_{desc}) > \theta \quad \text{VÀ} \quad \text{ContextMatch}(s_{file}, d_{process})
$$

*Ví dụ*:
*   **Tĩnh**: Tìm thấy `child_process.exec("curl " + url)` trong `install.js`.
*   **Động**: Phát hiện tiến trình `curl` được sinh ra với các đối số khớp với mẫu URL.
*   **Kết quả**: **ĐÃ XÁC NHẬN KHỚP** (Độ tin cậy Cao).

### 2.3. Tạo Phán quyết (Verdict Generation)
Phán quyết cuối cùng được xác định bởi "Ma trận Xác nhận":

| Độ nghiêm trọng Tĩnh | Xác nhận Động | Xác nhận Snyk | Phán quyết |
| :--- | :--- | :--- | :--- |
| HIGH/CRITICAL | Có | - | **ĐỘC HẠI (MALICIOUS)** |
| HIGH/CRITICAL | - | Có | **ĐỘC HẠI (MALICIOUS)** |
| MEDIUM | Có | - | **ĐÁNG NGỜ (SUSPICIOUS)** |
| HIGH | Không | Không | **ĐÁNG NGỜ** (Mã chết tiềm năng) |
| LOW | - | - | **LÀNH TÍNH (BENIGN)** |

### 2.4. Tổng hợp bằng LLM
Cuối cùng, hệ thống sử dụng LLM để tạo ra một **Báo cáo Toàn diện** dễ đọc cho con người.
*   Nó tóm tắt các khớp nối đã được xác nhận.
*   Nó giải thích *tại sao* commit được coi là độc hại (ví dụ: "Script cài đặt thực thi một reverse shell, điều này đã được xác nhận bởi giám sát thời gian chạy kết nối tới IP 1.2.3.4").

## 3. Đầu ra
Mô-đun tạo ra một báo cáo Markdown (`verification_report_*.md`) và mã trạng thái cuối cùng:
*   `is_malicious`: Cờ Boolean.
*   `malicious_confidence`: Số thực (0.0 - 1.0).
