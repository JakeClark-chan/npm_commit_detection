# Quy trình Tổng thể và Thuật toán

## 1. Tổng quan
**Hệ thống Phát hiện Commit Độc hại NPM** là một quy trình phân tích bảo mật toàn diện được thiết kế để phát hiện các mã độc được tiêm vào các bản cập nhật (commit) của gói phần mềm NPM. Hệ thống tích hợp nhiều kỹ thuật phân tích—phân tích tĩnh (tăng cường bởi LLM), phân tích động (giám sát thời gian chạy), và quét bảo mật bên thứ ba (Snyk)—thành một luồng công việc thống nhất nhằm tối đa hóa độ chính xác và giảm thiểu cảnh báo sai.

Triết lý cốt lõi là "Phòng thủ theo Chiều sâu" (Defense in Depth):
1.  **Tiền phân tích (Pre-analysis)**: Nhanh chóng lọc và sắp xếp ưu tiên các tệp dựa trên siêu dữ liệu và heuristic.
2.  **Phân tích Tĩnh (Static Analysis)**: Kiểm tra mã nguồn sâu bằng Mô hình Ngôn ngữ Lớn (LLM) để hiểu ngữ nghĩa và kỹ thuật làm mờ (obfuscation).
3.  **Phân tích Động (Dynamic Analysis)**: Giám sát hành vi thời gian chạy để bắt các hành động độc hại (kết nối mạng, truy cập tệp).
4.  **Xác minh (Verification)**: Một giai đoạn đối chiếu nơi LLM tương quan các phát hiện từ tất cả các công cụ để đưa ra phán quyết cuối cùng với độ tin cậy cao.

## 2. Kiến trúc Hệ thống

Quy trình được điều phối dưới dạng Đồ thị Không Chu trình Có hướng (DAG) hoặc quy trình thực thi song song tùy thuộc vào ngữ cảnh đầu vào (một commit đơn lẻ hay một phạm vi phiên bản).

### Thuật toán Mức Cao
Đầu vào: $R$ (Kho lưu trữ), $C$ (Commit mục tiêu hoặc Phạm vi phiên bản)
Đầu ra: $V$ (Phán quyết: ĐỘC HẠI/LÀNH TÍNH), $Report$ (Báo cáo)

1.  **Khởi tạo**:
    *   Kiểm tra tính hợp lệ của kho lưu trữ $R$.
    *   Xác định các commit mục tiêu $\{c_1, c_2, ..., c_n\}$ từ $C$.

2.  **Giai đoạn 1: Tiền phân tích (Mỗi Commit)**:
    *   Trích xuất siêu dữ liệu (tác giả, thời gian, thông điệp).
    *   Tính toán **Điểm Tin cậy Người đóng góp** ($T_{contributor}$).
    *   Xác định các tệp thay đổi và lọc theo đuôi tệp/độ nhạy cảm.
    *   *Mục tiêu*: Giảm không gian tìm kiếm cho các bước tốn kém về tính toán.

3.  **Giai đoạn 2: Phân tích Song song**:
    Hệ thống thực thi các mô-đun sau đồng thời sử dụng Thread Pool:
    
    *   **Mô-đun A: Phân tích Tĩnh (Dựa trên LLM)**
        *   **Giải mã (Deobfuscation)**: Nếu mã bị làm mờ (phát hiện bằng heuristic/entropy), áp dụng `DeobfuscatorAgent`.
            *   $Code_{clean} = Deobfuscate(Code_{obfuscated})$
        *   **Chấm điểm Rủi ro**: Các tệp cụ thể được ưu tiên dựa trên phần mở rộng và mẫu nội dung.
        *   **Quét LLM**: $Issues_{static} = LLM_{analyze}(Code_{clean}, Context)$
    
    *   **Mô-đun B: Phân tích Động (Package Hunter)**
        *   Đóng gói kho lưu trữ tại commit $c_i$ thành tệp tarball NPM.
        *   Thực thi bên trong hộp cát (container được giám sát bởi Falco).
        *   Ghi lại các lệnh gọi hệ thống (mạng, tệp, tiến trình).
        *   $Issues_{dynamic} = Normalize(Logs_{falco})$
    
    *   **Mô-đun C: Snyk SAST**
        *   Chạy công cụ Snyk Code trên các tệp đã thay đổi.
        *   $Issues_{snyk} = Snyk(Files_{changed})$

4.  **Giai đoạn 3: Xác minh & Tương quan**:
    *   Chuẩn hóa tất cả các phát hiện thành một lược đồ thống nhất $F = \{f | f \in Issues_{static} \cup Issues_{dynamic} \cup Issues_{snyk}\}$.
    *   **Đối sánh chéo**: Sử dụng LLM để tìm mối tương quan ngữ nghĩa giữa các phát hiện từ các nguồn khác nhau (ví dụ: Phân tích tĩnh phát hiện `eval()` khớp với Phân tích động phát hiện `execve`).
        *   $Match(f_a, f_b) \iff SemanticSimilarity(f_a, f_b) > Threshold$
    *   **Tạo Phán quyết**:
        *   Nếu $\exists (f_{static}, f_{dynamic})$ sao cho $Match(f_{static}, f_{dynamic})$ là ĐỘC HẠI $\implies$ **PHÁN QUYẾT = ĐỘC HẠI**.
        *   Nếu có Cảnh báo Tĩnh/Động độ tin cậy cao một cách độc lập $\implies$ **Cần Review**.

## 3. Các Thuật toán Cốt lõi

### 3.1. Logic Điều phối
Luồng thực thi chính được cài đặt trong `main.py` sử dụng `ThreadPoolExecutor` để tối ưu hóa hiệu năng.

```python
def run_analysis(config):
    # Chiến lược Thực thi Song song
    futures = {}
    with ThreadPoolExecutor() as executor:
        # Gửi tác vụ Phân tích Tĩnh
        futures[executor.submit(run_static_analysis, ...)] = 'static'
        
        # Gửi tác vụ Phân tích Động (nếu có cấu hình)
        if config.use_dynamic:
            futures[executor.submit(run_dynamic_analysis, ...)] = 'dynamic'
            
        # Gửi tác vụ Phân tích Snyk (nếu có cấu hình)
        if config.use_snyk:
            futures[executor.submit(run_snyk_analysis, ...)] = 'snyk'
            
    # Thu thập và Xác minh
    results = gather_results(futures)
    final_report = run_verification(results.static, results.dynamic, results.snyk)
    return final_report
```

### 3.2. Xác minh & Chấm điểm
Hệ thống chấm điểm cuối cùng dựa trên việc xác nhận các nghi ngờ từ phân tích tĩnh bằng bằng chứng từ phân tích động. Hệ thống tránh sử dụng tổng trọng số đơn giản mà thay vào đó sử dụng **Mô hình Xác nhận** (Confirmation Model).

Gọi $S$ là tập hợp các phát hiện tĩnh và $D$ là tập hợp các phát hiện động.
Chúng ta định nghĩa hàm đối sánh $M(s, d)$ thông qua một prompt LLM đánh giá xem liệu phát hiện $s \in S$ có giải thích cho sự kiện $d \in D$ hay không.

$$
Verdict = 
\begin{cases} 
\text{MALICIOUS} & \text{nếu } \exists s \in S, d \in D : M(s, d) = \text{True} \land Severity(s) \ge \text{HIGH} \\
\text{SUSPICIOUS} & \text{nếu } S \neq \emptyset \lor D \neq \emptyset \\
\text{BENIGN} & \text{ngược lại}
\end{cases}
$$

Cơ chế xác nhận nhị phân này ngăn chặn các kết quả dương tính giả (false positives) thường gặp trong phân tích tĩnh (mã chết - dead code) và phân tích động (script cài đặt lành tính).
