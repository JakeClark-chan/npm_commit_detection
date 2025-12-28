# Thiết lập Thực nghiệm (Experiment Setup)

## 1. Môi trường
Tất cả các thử nghiệm được tiến hành trên một máy trạm Linux với các thông số kỹ thuật sau để đảm bảo đo lường hiệu năng nhất quán:
*   **Hệ điều hành**: Linux (Kernel 6.x)
*   **Phần cứng**: 8 vCPUs, 16GB RAM.
*   **Phần mềm Phụ thuộc**:
    *   Python 3.10+
    *   Docker Engine (cho hộp cát Package Hunter)
    *   Falco (Giám sát Lời gọi Hệ thống)
    *   Snyk CLI (v1.1290.0)

## 2. Tập dữ liệu (Dataset)
Để đánh giá hiệu quả của hệ thống, chúng tôi đã chuẩn bị một tập dữ liệu đa dạng bao gồm cả các mẫu lành tính và độc hại.

### 2.1. Tập dữ liệu Mã độc (Lớp Dương tính)
Chúng tôi sử dụng tập dữ liệu **Malware-Packages** và các mẫu thực tế được xác định trong các cuộc tấn công chuỗi cung ứng gần đây.
*   **Tổng số mẫu độc hại**: 50 kho lưu trữ/commit.
*   **Các loại tấn công**:
    *   **Reverse Shell**: Tải trọng kết nối với C2 bên ngoài.
    *   **Trích xuất dữ liệu**: Đánh cắp `/etc/passwd` hoặc biến môi trường (ENV).
    *   **Bom Logic**: Hành vi độc hại chỉ kích hoạt trên môi trường production.
    *   **Typosquatting**: Các gói giả mạo thư viện phổ biến (ví dụ: `mongoose` so với các bản sao độc hại).

### 2.2. Tập dữ liệu Lành tính (Lớp Âm tính)
Chúng tôi đã chọn các gói Npm hàng đầu để kiểm tra các trường hợp dương tính giả (false positives).
*   **Kho lưu trữ**: `express`, `lodash`, `react`, `axios`.
*   **Tổng số mẫu lành tính**: 100 commit (lấy mẫu ngẫu nhiên từ lịch sử).

## 3. Các Chỉ số Đánh giá (Evaluation Metrics)
Chúng tôi đo lường hiệu năng sử dụng các chỉ số Truy hồi Thông tin tiêu chuẩn.

### 3.1. Ma trận Nhầm lẫn (Confusion Matrix)
*   **Dương tính Thật (TP)**: Commit độc hại được xác định chính xác là ĐỘC HẠI.
*   **Dương tính Giả (FP)**: Commit lành tính bị gắn cờ sai là ĐỘC HẠI/ĐÁNG NGỜ.
*   **Âm tính Thật (TN)**: Commit lành tính được xác định chính xác là LÀNH TÍNH.
*   **Âm tính Giả (FN)**: Commit độc hại bị bỏ qua (được gắn nhãn là LÀNH TÍNH).

### 3.2. Các Chỉ số Dẫn xuất
$$
\text{Precision (Độ chính xác)} = \frac{TP}{TP + FP}
$$

$$
\text{Recall (Độ thu hồi)} = \frac{TP}{TP + FN}
$$

$$
F1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
$$

### 3.3. Các Chỉ số Hiệu năng
*   **Độ trễ (Latency)**: Thời gian trung bình để phân tích một commit đơn lẻ (giây).
*   **Chi phí (Overhead)**: Mức sử dụng CPU/Bộ nhớ trong quá trình phân tích song song.
