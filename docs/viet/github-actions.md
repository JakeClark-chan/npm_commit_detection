# Tích hợp GitHub Actions

## 1. Tổng quan
Việc tích hợp **Hệ thống Phát hiện Commit NPM** vào đường ống Tích hợp Liên tục (CI) cho phép kiểm tra bảo mật tự động cho mọi thay đổi mã nguồn. Điều này đảm bảo rằng không có commit độc hại nào được triển khai lên môi trường production hoặc xuất bản lên registry NPM.

## 2. Kiến trúc CI
Quy trình CI hoạt động như một **Người gác cổng (Gatekeeper)**:
1.  **Kích hoạt (Trigger)**: Push vào nhánh `main` hoặc Pull Request thông thường.
2.  **Môi trường**: Ubuntu-latest runner (GitHub Actions).
3.  **Hành động**:
    *   Checkout mã nguồn.
    *   Cài đặt các phụ thuộc.
    *   Chạy `commit_detection` ở **Chế độ Xác thực (Validation Mode)**.
4.  **Thực thi (Enforcement)**:
    *   Nếu `is_malicious == True` $\rightarrow$ **Thất bại Build** & Thông báo Đội ngũ Bảo mật.
    *   Nếu `is_malicious == False` $\rightarrow$ **Thông qua Build**.

## 3. Cấu hình Workflow (`.github/workflows/security-scan.yaml`)

```yaml
name: NPM Security Scan

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
    - uses: actions/checkout@v3
    
    - name: Cài đặt Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Cài đặt Phụ thuộc
      run: |
        pip install -r requirements.txt
        npm install -g snyk

    - name: Chạy Phát hiện Commit
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      run: |
        python main.py --repo_path . --scan_latest
        
    - name: Tải lên Báo cáo
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: reports/verification_report_*.md
```

## 4. Xử lý Thất bại
Khi một commit độc hại được phát hiện, workflow sẽ trả về mã thoát khác không (ví dụ: `exit 1`).
*   **Giao diện GitHub**: PR bị chặn hợp nhất (merge).
*   **Artifacts**: Báo cáo xác minh chi tiết được tải lên để xem xét.
*   **Thông báo**: Có thể cấu hình để gửi cảnh báo tới Slack/Discord webhooks.
