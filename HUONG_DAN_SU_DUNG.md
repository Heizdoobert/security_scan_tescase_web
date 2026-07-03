# Hướng Dẫn Sử Dụng: Công Cụ Kiểm Tra Bảo Mật Web (Web Security Scanner)

Tài liệu này hướng dẫn chi tiết từ bước cài đặt môi trường, cách chạy lệnh kiểm tra, cho đến cách đọc và hiểu báo cáo bảo mật.

---

## 1. Yêu Cầu Hệ Thống (Requirements)
- **Python:** Phiên bản 3.10 trở lên.
- **Pip:** Trình quản lý gói của Python.

---

## 2. Hướng Dẫn Cài Đặt (Installation)

**Bước 1:** Mở terminal/PowerShell tại thư mục gốc của dự án (`D:\testcase_web\`).

**Bước 2:** Tạo và kích hoạt môi trường ảo (Virtual Environment) để không làm xung đột các thư viện Python trên máy tính:
* **Trên Windows:**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\activate
  ```
* **Trên Mac/Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

**Bước 3:** Cài đặt tất cả các thư viện cần thiết thông qua file `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 3. Cách Chạy Công Cụ (Running the Scanner)

Công cụ được thiết kế để chạy dưới dạng một module Python. Cú pháp cơ bản nhất để quét toàn bộ hệ thống và tạo báo cáo giao diện là:

```bash
python -m websec_test.main --target <URL_MUC_TIEU> --all --dashboard
```

**Ví dụ thực tế:**
Quét lỗ hổng trên trang đăng nhập và đăng ký:
```bash
python -m websec_test.main --target http://localhost:8080/note/login --all --dashboard
python -m websec_test.main --target http://localhost:8080/note/register --all --dashboard
```

### Các tùy chọn (Options) quan trọng:
- `--target`: Đường dẫn URL bạn muốn kiểm tra (Bắt buộc).
- `--all`: Chạy tất cả các kịch bản kiểm tra hiện có (SQLi, XSS, Headers, Methods, v.v.).
- `--dashboard`: Tạo báo cáo giao diện HTML tương tác.
- `--open`: Tự động mở báo cáo HTML trên trình duyệt ngay khi quét xong.
- `--auth user:pass`: Cung cấp thông tin đăng nhập (nếu hệ thống yêu cầu xác thực).

*Mẹo: Để xem toàn bộ các lệnh hỗ trợ, hãy chạy `python -m websec_test.main --help`.*

---

## 4. Xem và Hiểu Báo Cáo (Viewing the Report)

Sau khi quá trình quét hoàn tất, các báo cáo sẽ tự động được lưu vào thư mục `reports/` trong dự án.

### Mở Báo Cáo HTML:
Tìm file có định dạng `dashboard_YYYYMMDD_HHMMSS.html` trong thư mục `reports/` và mở nó bằng bất kỳ trình duyệt web nào (Chrome, Edge, Firefox).

* Tính năng Tương Tác: Tại giao diện báo cáo, bạn có thể nhấp vào biểu tượng `▶` ở mỗi dòng để mở chi tiết.
* Lọc Kết Quả: Bạn có thể chọn chỉ hiển thị các bài kiểm tra bị Lỗi (Fail), hoặc Cảnh báo (Warn) thông qua các ô checkbox ở trên cùng.

### Hiểu Logic [PASS] và [FAIL] (Rất quan trọng):
Báo cáo tuân theo chuẩn quy ước của kiểm thử bảo mật (Security Auditing):
- 🟢 **[PASS] = SECURE (An Toàn):** Hệ thống của bạn đã vượt qua bài kiểm tra. Nghĩa là ứng dụng đã chặn đứng được đợt tấn công giả lập, hoặc đã cấu hình đúng tiêu chuẩn bảo mật.
- 🔴 **[FAIL] = VULNERABLE (Có Lỗ Hổng):** Hệ thống của bạn đã thất bại trong bài kiểm tra. Nghĩa là đợt tấn công giả lập đã lọt qua, hoặc ứng dụng đang thiếu các cấu hình bảo mật bắt buộc.

Bên trong chi tiết mỗi bài test (khi bấm `▶`), hệ thống sẽ hiển thị mục **Logic Explanation** giải thích rõ ràng lý do, đồng thời đính kèm mục **Recommendation** (Khuyến nghị) để bạn biết cách vá lỗ hổng (Fix) trong mã nguồn backend của mình. Đồng thời bạn có thể xem chi tiết phần **HTTP Request & Response** để hiểu rõ payload nào đã được gửi đi và server đã phản hồi như thế nào.

---

## 5. Dọn Dẹp và Chạy Lại (Re-running)

Trong quá trình bạn sửa lỗi trên backend và muốn quét lại để kiểm tra xem lỗi đã hết chưa, bạn có thể xóa các báo cáo cũ đi cho đỡ rối, sau đó chạy lại lệnh quét:

* **Xóa báo cáo cũ (Trên PowerShell):**
  ```powershell
  Remove-Item -Path "reports\*" -Recurse -Force
  ```
* **Chạy lại:**
  ```bash
  python -m websec_test.main --target http://localhost:8080/note/login --all --dashboard
  ```
