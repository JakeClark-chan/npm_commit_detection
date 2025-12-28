# Giai đoạn Phân tích Tĩnh (Static Analysis)

## 1. Tổng quan
**Giai đoạn Phân tích Tĩnh** đóng vai trò là động cơ kiểm tra cốt lõi của hệ thống. Không giống như các công cụ SAST truyền thống chỉ dựa vào so khớp mẫu (regex), mô-đun này tận dụng khả năng hiểu ngữ nghĩa của các Mô hình Ngôn ngữ Lớn (LLM) để phát hiện các hành vi độc hại phức tạp, chẳng hạn như bom logic (logic bombs), tải trọng bị làm mờ (obfuscated payloads), và các cửa hậu (backdoors) tinh vi mà regex thường bỏ sót.

## 2. Phương pháp luận

Quy trình phân tích tĩnh (`llm/static_analysis.py`) tuân theo cách tiếp cận có cấu trúc:
1.  **Giải mã (Deobfuscation)**: Tiền xử lý mã để lộ ra các ý định ẩn giấu (chi tiết trong [Tài liệu Giải mã](./deobfuscation.md)).
2.  **Lọc Tệp & Chấm điểm Rủi ro**: Ưu tiên các tệp cần phân tích để tối ưu hóa Token và Hiệu năng.
3.  **Phát hiện Mẫu**: Quét heuristic nhanh các từ khóa đáng ngờ.
4.  **Kiểm tra Sâu bằng LLM**: Gửi các đoạn mã thay đổi có rủi ro cao tới LLM để phân tích ngữ nghĩa.

### 2.1. Thuật toán Chấm điểm Rủi ro Tệp (File Risk Scoring)
Để xử lý hiệu quả các commit lớn, chúng tôi tính toán **Điểm Rủi ro ($S_{risk}$)** cho mỗi tệp bị thay đổi. Chỉ những tệp có điểm số cao nhất mới được chuyển tiếp đến LLM.

Điểm rủi ro cho một tệp $f$ được tính như sau:

$$
S_{risk}(f) = S_{ext}(f) + S_{content}(f) + S_{sensitive}(f)
$$

Trong đó:
*   **$S_{ext}(f)$ (Điểm Phần mở rộng)**:
    *   Cấu hình Build (`.vscode`, `tasks.json`): $10$ điểm
    *   Script Hệ thống (`.sh`, `.bash`): $8$ điểm
    *   Logic Cốt lõi (`.js`, `.ts`): $5$ điểm
    *   Web/Khác (`.html`, `.php`): $3$ điểm
    *   Mặc định: $1$ điểm
*   **$S_{content}(f)$ (Điểm Nội dung)**: Dựa trên các khớp mẫu regex.
    *   $S_{content} = 2 \times N_{matches}$, trong đó $N_{matches}$ là số lượng danh mục đáng ngờ duy nhất được tìm thấy (ví dụ: `eval`, `network`).
*   **$S_{sensitive}(f)$**: $+5$ điểm nếu tệp nằm trong danh sách theo dõi "Tệp Nhạy cảm".

**Chiến lược Lựa chọn**: Hệ thống chọn **Top N** (mặc định: 10) tệp có $S_{risk}$ cao nhất để phân tích LLM.

### 2.2. Phát hiện Mẫu Đáng ngờ (Suspicious Pattern Detection)
Chúng tôi sử dụng một từ điển các Biểu thức Chính quy (RegEx) để xác định các khả năng đáng ngờ trước khi phân tích LLM. Các danh mục bao gồm:
*   **Thực thi (Execution)**: `eval`, `exec`, `spawn`, `Function(string)`.
*   **Mạng (Network)**: `http.get`, `curl`, `wget`, `fetch`, `axios`.
*   **Làm mờ (Obfuscation)**: `\x[0-9a-f]`, `base64`, `rot13`, `fromCharCode`.
*   **Môi trường (Environment)**: `process.env`, `/etc/shadow`, `whoami`.

### 2.3. Logic Phân tích LLM
Các thay đổi mã được lọc sẽ được hợp nhất thành một ngữ cảnh prompt có cấu trúc.

**Ngữ cảnh Đầu vào**:
*   Siêu dữ liệu Commit (Tác giả, Thông điệp).
*   Diff hợp nhất của các tệp Rủi ro Cao (đã làm sạch để loại bỏ nhiễu từ các dòng bị xóa).
*   Các phát hiện Mẫu Đáng ngờ toàn cục.

**Mô hình**: OpenAI GPT-4o-mini (tối ưu hóa tốc độ/chi phí) hoặc GPT-4o (độ chính xác cao hơn).

**Cấu trúc Prompt**:
> "Bạn là một chuyên gia an ninh mạng chuyên phát hiện các cuộc tấn công chuỗi cung ứng... Phân tích các thay đổi mã sau đây để tìm ý định độc hại. Bỏ qua thay đổi phong cách mã. Tập trung vào: thực thi mã tùy ý, trích xuất dữ liệu, và làm mờ mã. Trả về kết quả dưới dạng JSON."

### 2.4. Phân tích Import
Song song đó, hệ thống phân tích cú pháp các câu lệnh Import/Require để phát hiện các phụ thuộc mới.
*   **Mục tiêu**: Phát hiện "Typosquatting" hoặc các gói độc hại đã biết.
*   **Heuristic**: Kiểm tra các import so với danh sách giám sát các thuật ngữ đáng ngờ (`crypto`, `child_process`, `net`) và gắn cờ chúng cho giai đoạn xác minh.

## 3. Đầu ra
Mô-đun Phân tích Tĩnh tạo ra một đối tượng JSON chứa:
*   `total_issues`: Số lượng lỗ hổng được phát hiện.
*   `issues`: Danh sách các đối tượng `SecurityIssue`, mỗi đối tượng chứa:
    *   `severity`: CRITICAL (Nghiêm trọng), HIGH (Cao), MEDIUM (Trung bình), LOW (Thấp).
    *   `category`: Loại tấn công (ví dụ: `code_injection`).
    *   `file_path`, `line_number`.
    *   `description`: Giải thích do LLM tạo ra.
    *   `recommendation`: Các bước khắc phục.
