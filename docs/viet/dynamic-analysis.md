# Giai đoạn Phân tích Động (Dynamic Analysis)

## 1. Tổng quan
Phân tích tĩnh, mặc dù mạnh mẽ, có thể bị qua mặt bởi các kỹ thuật làm mờ tinh vi hoặc mã tạo logic tại thời gian chạy (runtime). **Giai đoạn Phân tích Động** giải quyết hạn chế này bằng cách thực thi mã trong môi trường hộp cát (sandbox) được kiểm soát và giám sát hành vi thời gian thực của nó.

## 2. Ngăn xếp Công nghệ (Technology Stack)
Chúng tôi sử dụng **Package Hunter**, một công cụ giám sát hành vi dựa trên Falco được thiết kế riêng cho các gói Npm.
*   **Engine**: `sysdig/package-hunter`.
*   **Trình giám sát**: Sysdig Falco (Chặn cuộc gọi hệ thống ở cấp độ hạt nhân - Kernel-level).
*   **Mục tiêu giám sát**: Kết nối mạng, Sửa đổi hệ thống tệp, Tạo tiến trình.

## 3. Quy trình Làm việc

Mô-đun phân tích động (`tools/dynamic_analysis.py`) thực thi vòng đời sau:

1.  **Chuẩn bị**:
    *   Checkout kho lưu trữ tại commit cụ thể $C$.
    *   Thực thi `npm pack` để tạo tệp nén tarball ($P_{tgz}$), mô phỏng chính xác những gì sẽ được xuất bản lên registry.

2.  **Đệ trình**:
    *   Tải $P_{tgz}$ lên máy chủ Package Hunter cục bộ thông qua API ($P_{tgz} \rightarrow \text{localhost:3000}$).

3.  **Thực thi & Giám sát**:
    *   Package Hunter cài đặt gói trong một Docker container.
    *   Nó thực thi các móc vòng đời (lifecycle hooks) riêng biệt: `preinstall`, `install`, `postinstall`, và `test`.
    *   Driver Falco chặn các cuộc gọi hệ thống khớp với các quy tắc bảo mật.

4.  **Tổng hợp Kết quả**:
    *   Hệ thống thăm dò API để lấy trạng thái phân tích.
    *   Khi hoàn tất, nó truy xuất báo cáo JSON chứa danh sách các **Sự kiện (Events)**.

## 4. Khả năng Phát hiện

Hệ thống phát hiện các "IOC" (Chỉ báo xâm phạm) được ánh xạ tới các quy tắc Falco:

### 4.1. Hoạt động Mạng
*   **Kết nối ra ngoài đáng ngờ**: Kết nối đến các cổng không chuẩn hoặc các IP C2 (Command & Control) đã biết.
*   **Trích xuất dữ liệu qua DNS**: Khối lượng yêu cầu DNS cao bất thường.

### 4.2. Hệ thống Tệp
*   **Đọc nhạy cảm**: Truy cập vào `/etc/shadow`, `~/.ssh/id_rsa`, `.env`.
*   **Duy trì sự hiện diện (Persistence)**: Ghi vào `/etc/cron.d`, `~/.bashrc`.

### 4.3. Thực thi Tiến trình
*   **Tạo Shell**: `sh -c`, `bash`, `cmd.exe` được kích hoạt bởi các script cài đặt.
*   **Reverse Shells**: Các đường ống (pipes) kết nối với socket mạng.

## 5. Xử lý Hạn chế
Phân tích động tốn kém về mặt tính toán và yêu cầu một máy chủ đang chạy.
*   **Tối ưu hóa**: Nó chỉ được kích hoạt nếu một hash commit cụ thể được cung cấp (chế độ mục tiêu).
*   **Thời gian chờ (Timeout)**: Phân tích được giới hạn ở 300 giây để ngăn chặn tấn công từ chối dịch vụ bằng vòng lặp vô hạn.
