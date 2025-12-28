# Giai đoạn Tiền Phân tích (Pre-Analysis)

## 1. Tổng quan
**Giai đoạn Tiền Phân tích** hoạt động như một lớp lọc nhanh được thiết kế để xác định các commit "nguy cơ cao" và giảm tải tính toán cho các giai đoạn phân tích chuyên sâu tốn kém hơn (Phân tích Tĩnh và Động). Bằng cách phân tích siêu dữ liệu, mô hình người đóng góp và thống kê tệp, hệ thống cung cấp một đánh giá rủi ro sơ bộ.

## 2. Phương pháp luận

Mô-đun tiền phân tích (`analyzers/pre_analysis.py`) thực hiện ba đánh giá chính:

1.  **Phân tích Siêu dữ liệu**: Kiểm tra thông điệp commit và dấu thời gian sử dụng Git metadata.
2.  **Chấm điểm Tin cậy Người đóng góp**: Đánh giá độ uy tín của người thực hiện commit.
3.  **Phân tích Thay đổi**: Định lượng lượng mã thay đổi và phát hiện việc sử dụng các tệp nhạy cảm.

### 2.1. Chấm điểm Tin cậy Người đóng góp (Contributor Trust Scoring)
Chúng tôi triển khai một hệ thống chấm điểm tin cậy dựa trên heuristic để xác định các "mối đe dọa nội bộ" tiềm tàng hoặc các tài khoản bị xâm nhập, cũng như những người đóng góp mới có thể đưa mã độc vào.

Đối với một người đóng góp $C$, Điểm Tin cậy $T_C$ được tính như sau:

$$
T_C = \min\left(\frac{N_{commits}}{50}, 1.0\right)
$$

Trong đó:
*   $N_{commits}$: Tổng số lượng commit của người đóng góp đó trong lịch sử kho lưu trữ.
*   Điểm số dao động từ $0.0$ (Không tin cậy/Mới) đến $1.0$ (Hoàn toàn tin cậy).
*   **Các ngưỡng (Thresholds)**:
    *   $T_C \ge 0.7$: Người đóng góp Tin cậy.
    *   $T_C < 0.3$: Người đóng góp Ít tin cậy/Đáng ngờ.
    *   Người đóng góp Mới: Được định nghĩa là có tổng số commit $< 5$.

### 2.2. Phát hiện Tệp Nhạy cảm (Sensitive File Detection)
Hệ thống duy trì một danh sách các mẫu tệp nhạy cảm (RegEx) thường là mục tiêu của việc tiêm mã độc (ví dụ: script build, tệp cấu hình).

**Thuật toán Phát hiện**:
Đầu vào: Danh sách các tệp thay đổi $F = \{f_1, f_2, ...\}$
Đầu ra: Tập hợp các tệp nhạy cảm $S \subseteq F$

Gọi $P$ là tập hợp các mẫu nhạy cảm (ví dụ: `package.json`, `install.sh`, `.env`, `.github/workflows/.*`).
Một tệp $f_i$ bị gắn cờ nếu:
$$
\exists p \in P : \text{match}(f_i, p) = \text{True}
$$

**Cảnh báo Nghiêm trọng**:
*   Sửa đổi đối với `package.json` kích hoạt cảnh báo kiểm tra phụ thuộc (dependency check).
*   Sửa đổi đối với các script build (`install.sh`, `setup.js`) kích hoạt cảnh báo ưu tiên cao.

### 2.3. Phát hiện Bất thường trong Thay đổi (Change Anomaly Detection)
Chúng tôi phân tích khối lượng thay đổi mã để phát hiện các bất thường như "Commit Lớn", nơi kẻ tấn công có thể cố gắng giấu mã độc trong một lần tái cấu trúc mã (refactor) khổng lồ.

**Chỉ số**: Thay đổi ròng $ \Delta = \sum Additions - \sum Deletions $
**Quy tắc Bất thường**:
$$
\text{IsLargeCommit}(c) = 
\begin{cases} 
\text{True} & \text{nếu } (Additions + Deletions) > 500 \\
\text{False} & \text{ngược lại}
\end{cases}
$$

## 3. Chi tiết Cài đặt
Lớp `PreAnalyzer` điều phối các kiểm tra này.

*   `get_commit_metadata(sha)`: Trích xuất các trường chuẩn từ Git.
*   `build_contributor_profiles(shas)`: Tổng hợp dữ liệu lịch sử để tính $T_C$.
*   `_analyze_changes(shas)`: Tính toán các chỉ số thống kê về sự biến động mã nguồn.

## 4. Đầu ra
Kết quả là một cấu trúc JSON và báo cáo văn bản chứa:
*   Danh sách người đóng góp mới/không tin cậy.
*   Danh sách các tệp nhạy cảm bị sửa đổi.
*   Danh sách các commit lớn bất thường.
*   **Tín hiệu Hành động**: Nếu các tệp quan trọng bị sửa đổi hoặc người đóng góp không đáng tin, giai đoạn Phân tích Tĩnh tiếp theo sẽ nâng cao **Điểm Rủi ro (Risk Score)** cho các tệp bị ảnh hưởng.
