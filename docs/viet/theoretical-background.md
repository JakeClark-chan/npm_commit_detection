# Chương 2. Cơ sở Lý thuyết

Chương này trình bày các kiến thức nền tảng cần thiết để xây dựng và vận hành hệ thống phát hiện commit độc hại. Nội dung bao gồm tổng quan về hệ sinh thái kiểm soát phiên bản và quản lý gói, các lý thuyết về an ninh chuỗi cung ứng, cùng các phương pháp phân tích bảo mật ứng dụng (SAST và DAST).

## 2.1. Kho lưu trữ Git, GitHub và npm

Để hiểu rõ về dữ liệu đầu vào và môi trường hoạt động của hệ thống, cần nắm vững các khái niệm về Git, GitHub và npm.

### 2.1.1. Git
Git là hệ thống quản lý phiên bản phân tán (Distributed Version Control System - DVCS) phổ biến nhất hiện nay.
*   **Commit**: Trong ngữ cảnh của hệ thống này, "Commit" là đơn vị phân tích cơ bản. Một commit chứa thông tin về những thay đổi trong mã nguồn (diff), tác giả (metadata), và thời gian thực hiện. Hệ thống dựa vào các thông tin này để tính toán điểm tin cậy và phát hiện bất thường.
*   **Diff**: Bản ghi các dòng mã được thêm vào hoặc xóa đi. Phân tích tĩnh của chúng tôi hoạt động chủ yếu trên nội dung của `git diff` để xác định các đoạn mã độc hại mới được đưa vào.

### 2.1.2. GitHub
GitHub là nền tảng lưu trữ mã nguồn dựa trên Git, đóng vai trò trung tâm trong quy trình phát triển phần mềm hiện đại (DevOps).
*   **Pull Request (PR)**: Cơ chế đề xuất thay đổi mã nguồn. Đây là "cổng kiểm soát" (gatekeeping) lý tưởng để tích hợp các công cụ quét bảo mật.
*   **GitHub Actions**: Nền tảng CI/CD tích hợp sẵn, cho phép tự động hóa quy trình kiểm tra ngay khi có mã mới được đẩy lên (push).

### 2.1.3. npm (Node Package Manager)
npm là trình quản lý gói mặc định cho môi trường Node.js và là hệ sinh thái mã nguồn mở lớn nhất thế giới.
*   **package.json**: Tệp cấu hình quan trọng nhất, định nghĩa các phụ thuộc (dependencies) và kịch bản (scripts) của dự án.
*   **Lifecycle Scripts**: npm cho phép định nghĩa các script chạy tự động như `preinstall`, `postinstall`. Đây là vector tấn công phổ biến nhất của mã độc npm, nơi kẻ tấn công chèn lệnh tải xuống payload độc hại (dropper) ngay khi người dùng gõ lệnh `npm install`.

## 2.2. Software Supply Chain Security (An ninh Chuỗi cung ứng Phần mềm)

An ninh chuỗi cung ứng tập trung vào việc bảo vệ và đảm bảo tính toàn vẹn của phần mềm từ giai đoạn phát triển đến khi phân phối.

### 2.2.1. Hệ sinh thái npm
Do tính chất mở và phi tập trung, bất kỳ ai cũng có thể xuất bản một gói lên npm registry. Sự phụ thuộc chồng chéo (transitive dependencies) khiến một dự án có thể gián tiếp sử dụng hàng ngàn gói từ các tác giả không xác định, tạo bề mặt tấn công rất rộng.

### 2.2.2. Các vector tấn công phổ biến
*   **Typosquatting**: Kẻ tấn công đặt tên gói gần giống với các gói phổ biến (ví dụ: `react` -> `rceact`) để lừa lập trình viên cài đặt nhầm.
*   **Tài khoản dev bị chiếm quyền (Compromised Maintainer Accounts)**: Kẻ tấn công chiếm quyền điều khiển tài khoản của một tác giả tin cậy (thông qua lộ lọt mật khẩu hoặc token) và đẩy mã độc vào các bản cập nhật mới của các gói hợp pháp.
*   **Malicious Commit**: Kẻ tấn công hoặc người nội bộ chèn một đoạn mã độc nhỏ vào giữa hàng ngàn dòng mã thay đổi hợp lệ trong một commit nhằm qua mắt quy trình review. Đây là vấn đề chính mà khóa luận này giải quyết.

## 2.3. Static Application Security Testing (SAST - Kiểm thử Bảo mật Ứng dụng Tĩnh)

SAST là phương pháp phân tích mã nguồn để tìm lỗ hổng bảo mật mà không cần thực thi chương trình.

### 2.3.1. Phương pháp truyền thống (Pattern Matching/RegEx)
*   **Lý thuyết**: Sử dụng các biểu thức chính quy (Regular Expressions) và so khớp mẫu để tìm các từ khóa nguy hiểm hoặc các mẫu cú pháp đã biết (ví dụ: tìm hàm `eval()`, `exec()`).
*   **Hạn chế**:
    *   **Nhiễu cao (High False Positives)**: Không phân biệt được mã an toàn và mã độc nếu chúng dùng chung từ khóa.
    *   **Dễ bị qua mặt**: Kẻ tấn công có thể thay đổi tên biến hoặc cấu trúc mã để tránh khớp với mẫu (signature).
    *   **Thiếu ngữ cảnh**: Không hiểu luồng dữ liệu hoặc mục đích của đoạn mã.

### 2.3.2. Phân tích dựa trên LLM (Large Language Models)
*   **Lý thuyết**: Sử dụng các mô hình ngôn ngữ lớn (như GPT) đã được huấn luyện trên lượng lớn mã nguồn để phân tích. LLM có khả năng "đọc hiểu" đoạn mã như một lập trình viên.
*   **Ưu điểm**:
    *   **Hiểu ngữ nghĩa (Semantics)**: Phân biệt được hành vi độc hại thực sự dựa trên ngữ cảnh sử dụng (ví dụ: `exec` dùng để build dự án vs `exec` dùng để gửi dữ liệu ra ngoài).
    *   **Phát hiện biến thể**: Có thể nhận diện các đoạn mã bị làm mờ hoặc viết lại theo cách khác thường mà phương pháp RegEx bỏ sót.

## 2.4. Dynamic Application Security Testing (DAST - Kiểm thử Bảo mật Ứng dụng Động)

DAST phân tích hành vi của ứng dụng trong trạng thái đang chạy (runtime) để phát hiện các hành động bất thường.

### 2.4.1. Cơ chế Sandbox (Hộp cát)
Sandbox là một môi trường thực thi cô lập (thường sử dụng Containerization như Docker) nhằm ngăn chặn mã độc gây hại cho hệ thống chủ. Mọi hành động của gói phần mềm đều được giới hạn và giám sát bên trong môi trường này.

### 2.4.2. Giám sát System Call (Lời gọi Hệ thống)
Mã độc, bất kể được viết bằng ngôn ngữ gì hay bị làm mờ ra sao, cuối cùng đều phải tương tác với hệ điều hành thông qua các System Call (ví dụ: `open` để đọc file, `connect` để mở kết nối mạng, `execve` để tạo tiến trình).
*   Công cụ: Hệ thống sử dụng **Falco** (dựa trên công nghệ eBPF hoặc kernel module) để lắng nghe và ghi lại các sự kiện system call này, từ đó phát hiện hành vi độc hại (ví dụ: một script cài đặt cố gắng đọc `/etc/shadow`).

## 2.5. Phòng thủ theo chiều sâu và Kỹ thuật xác minh

Một công cụ đơn lẻ (Static hoặc Dynamic) thường không đủ để đảm bảo độ chính xác cao.

### 2.5.1. Mô hình tương quan (Correlation Model)
*   **Lý thuyết**: Kết hợp kết quả từ nhiều công cụ phân tích khác nhau để đưa ra phán quyết cuối cùng. Một hành vi chỉ bị coi là độc hại khi có bằng chứng từ nhiều nguồn củng cố lẫn nhau.
    *   Ví dụ: Phân tích tĩnh nghi ngờ một đoạn mã tải file, và Phân tích động xác nhận có kết nối mạng ra ngoài.
*   **Học kết hợp (Ensemble Method)**: Hệ thống hoạt động như một hội đồng các chuyên gia, nơi mỗi module phân tích đóng vai trò một giám khảo. Phán quyết cuối cùng dựa trên sự đồng thuận hoặc các quy tắc ưu tiên (priority rules), giúp giảm thiểu đáng kể tỷ lệ dương tính giả (False Positives).

## 2.6. Tự động hóa quy trình (CI/CD Integration)

Tích hợp bảo mật vào quy trình DevOps (DevSecOps) là xu hướng tất yếu. Bằng cách nhúng công cụ phát hiện vào CI/CD pipeline (như GitHub Actions), việc kiểm tra an ninh trở thành một phần bắt buộc và tự động mỗi khi có thay đổi mã nguồn, đảm bảo nguyên tắc "Shift Left" - phát hiện lỗi sớm nhất có thể.
