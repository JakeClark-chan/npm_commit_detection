Các điểm yếu chính của mô hình:
* Do tính tự nhiên của phương pháp Heuristic File Filtering nên có thể bị lừa: commit có thể có mã độc ở mục + nhưng sau khi phát hiện thì đã xóa mã độc đó nên ở muc -, và LLM không thể nhìn thấy sự tương quan giữa 2 commit này.
* Mặc dù mô hình có cơ chế phát hiện rối mã (obfuscation) nhưng vẫn có thể bị lừa: phần rối mã đó thực chất có thể là mã lành tính đã được người dùng cố tình làm rối để tránh phát hiện.

Hướng phát triển của mô hình:
* Ở giữa pre-analysis và static analysis là một bước lọc nhiễu, cũng như có thêm 1 con deobfuscator agent để giải rối mã (làm rồi mà vì chưa có kết quả nên thôi đừng viết)