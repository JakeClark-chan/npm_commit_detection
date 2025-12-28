# Mô-đun Giải mã (Deobfuscation)

## 1. Tổng quan
Kẻ tấn công thường làm mờ (obfuscate) mã độc để trốn tránh các cơ chế phát hiện tĩnh (heuristic và so khớp chữ ký). **Mô-đun Giải mã** là một tác nhân được thiết kế để chuẩn hóa mã JavaScript bị làm mờ thành định dạng mà con người và máy có thể đọc được trước khi chuyển nó đến bộ Phân tích Tĩnh chính.

## 2. Chiến lược Phát hiện
Hệ thống trước tiên thực hiện **Quét Entropy** nhẹ để quyết định xem việc giải mã có cần thiết hay không.

**Heuristic**:
*   **Cấu trúc**: Tần suất cao của các biến `_0x`, chuỗi hex escape `\xNN`.
*   **Từ khóa**: Sự hiện diện của `atob`, `btoa`, `eval`, `Buffer.from(..., 'base64')`.
*   **Mật độ**: Điều chỉnh điểm số cho mã bị "nén" (độ dài dòng trung bình cao).

$$
Score_{obfuscation} = 0.4 \times I_{_0x} + 0.3 \times I_{hex} + 0.3 \times I_{packed} + 0.5 \times I_{decoder}
$$

Nếu $Score \ge 0.5$, tệp sẽ được gắn cờ để giải mã.

## 3. Quy trình Giải mã
Sau khi được gắn cờ, mã trải qua quy trình 3 giai đoạn:

### 3.1. Giai đoạn 1: Giải mã bằng Công cụ
Chúng tôi sử dụng các công cụ mã nguồn mở chuyên dụng (ví dụ: `javascript-deobfuscator`, `synchrony`) để xử lý các kỹ thuật đóng gói (packing) phổ biến.
*   **Hành động**: Đảo ngược việc đổi tên biến, tháo gỡ luồng điều khiển (un-flattens control flow), và đơn giản hóa các vòng xoay mảng.
*   **Kết quả**: $Code_{stage1} = Tool(Code_{original})$

### 3.2. Giai đoạn 2: Giải mã Chuỗi Tĩnh
Kẻ tấn công thường giấu tải trọng (payload) trong các chuỗi Base64 hoặc Hex mà các công cụ giải mã có thể làm lộ ra nhưng không giải mã nội dung. Giai đoạn này quét $Code_{stage1}$ để tìm các chuỗi được mã hóa.

*   **Thuật toán**:
    *   **Base64**: Quét các mẫu `[A-Za-z0-9+/=]{20,}` và thử giải mã.
    *   **Hex**: Phát hiện chuỗi các ký tự escape `\xNN` và chuyển đổi sang ASCII.
    *   **URL/HTML**: Giải mã `%XX` và các thực thể HTML.
*   **Chú thích**: Các chuỗi đã giải mã được chèn dưới dạng bình luận (comment) ngay cạnh mã gốc để hỗ trợ ngữ cảnh cho LLM.
    ```javascript
    const payload = "ZWNobyBoYWNrZWQ="; // [DECODED BASE64]: echo hacked
    ```

### 3.3. Giai đoạn 3: Tinh chỉnh bằng LLM
Nếu đầu ra của công cụ vẫn khó hiểu, LLM sẽ được gọi để thực hiện "Tinh chỉnh Ngữ nghĩa".
*   **Tác vụ**: Đổi tên biến dựa trên ngữ cảnh (ví dụ: đổi `_0x1a2b` thành `fetchUrl`) và đơn giản hóa logic.
*   **Kết quả**: $Code_{final} = LLM_{refine}(Code_{stage2})$

## 4. Tích hợp
Nội dung đã giải mã sẽ tạm thời thay thế nội dung tệp gốc trong đường ống phân tích. Điều này đảm bảo rằng LLM Phân tích Tĩnh đánh giá *ý định* của mã thay vì hình thức bị làm mờ của nó.
