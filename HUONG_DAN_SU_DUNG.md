# Hướng Dẫn Sử Dụng: Công Cụ Kiểm Tra Bảo Mật Web (Web Security Scanner)

Tài liệu này hướng dẫn chi tiết từ bước cài đặt môi trường, cách chạy lệnh kiểm tra, cho đến cách đọc và hiểu báo cáo bảo mật.

---

## 1. Yêu Cầu Hệ Thống (Requirements)
- **Python:** Phiên bản 3.10 trở lên.
- **Pip:** Trình quản lý gói của Python.
- **Docker:** Để chạy OWASP Juice Shop (môi trường test mục tiêu).
- **Ollama:** Để chạy mô hình LLM local (qwen2.5-coder:7b) cho pipeline PentestGPT.

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

### 3.1. Quét Web Tổng Quát

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

## 4. Kiểm Thử OWASP Juice Shop (12 Test Cases từ Excel)

### 4.1. Giới Thiệu

Bộ test này được ánh xạ trực tiếp từ file `Pentest_TestCases_JuiceShop.xlsx`, bao gồm **12 test case** bảo mật tương ứng với các lỗ hổng OWASP Juice Shop. Các test case được chia làm 4 nhóm:

| Nhóm | Test Case | Mô tả |
|------|-----------|-------|
| **Injection** | TC_SEC_INJ_01, INJ_02, INJ_03, INJ_04 | SQLi login bypass, GDPR deleted account, UNION SELECT fabrication, SSTI RCE |
| **Broken Access Control** | TC_SEC_BAC_01 | Tự đăng ký tài khoản admin |
| **Broken Authentication** | TC_SEC_AUTH_01, AUTH_02, AUTH_03, AUTH_04 | OAuth reverse, TOTP bypass, JWT none, JWT RS→HS |
| **Sensitive Data Exposure** | TC_SEC_SDE_01, SDE_02 | FTP document leak, GPS EXIF password reset |
| **XSS** | TC_SEC_XSS_01 | DOM XSS iframe injection |

### 4.2. Yêu Cầu

- **Docker** đã cài đặt và sẵn sàng
- **Ollama** đang chạy với model `qwen2.5-coder:7b` (hoặc model tương thích khác)

### 4.3. Các Bước Thực Hiện

**Bước 1: Khởi động OWASP Juice Shop**
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

**Bước 2 (Tùy chọn): Cấu hình model và target**
File `Demo_auto/.env` đã được cấu hình sẵn:
```
TARGET_URL=http://localhost:3000
MODEL=ollama:qwen2.5-coder:7b
```
Bạn có thể thay đổi nếu cần (ví dụ dùng model khác hoặc Juice Shop chạy ở port khác).

**Bước 3: Chạy toàn bộ 12 test case tự động**

```bash
# Chạy unit test (không cần LLM) — kiểm tra logic module PentestgptModule
python -m pytest tests/test_pentestgpt.py -v

# Chạy integration test (cần Ollama + Juice Shop đang chạy)
python -m pytest tests/test_pentestgpt_auto.py -v --integration
```

**Bước 4: Kiểm tra báo cáo kết quả**

Kết quả được lưu trong thư mục `Demo_auto/` dưới dạng JSON:
```
Demo_auto/pentestgpt_report_<timestamp>.json
```

### 4.4. Chi Tiết Từng Test Case

Dưới đây là mô tả chi tiết từng test case theo đúng file Excel:

#### TC_SEC_INJ_01 — SQL Injection Login Bypass
- **Mục tiêu:** Kiểm tra xem form login có bị SQLi cho phép bypass authentication không
- **Endpoint:** `POST /rest/user/login`
- **Payload:** `{"email": "admin@juice-sh.op' OR '1'='1 --", "password": "x"}`
- **Các bước thủ công:**
  1. Dùng Burp Suite bắt request login
  2. Sửa email field thành `admin@juice-sh.op' OR '1'='1 --`
  3. Forward request, kiểm tra response có JWT token không
- **Kết quả mong đợi (khi có lỗ hổng):** HTTP 200 + JWT token cho admin

#### TC_SEC_BAC_01 — Admin Registration (Broken Access Control)
- **Mục tiêu:** Kiểm tra endpoint đăng ký có cho phép tự set role admin không
- **Endpoint:** `POST /api/Users`
- **Payload:** `{"email": "hacker@test.com", "password": "test123", "role": "admin"}`
- **Các bước thủ công:**
  1. Vào trang register, fill form
  2. Dùng Burp Suite bắt request POST register
  3. Sửa `"role": "customer"` thành `"role": "admin"`
  4. Forward request
  5. Đăng nhập với tài khoản vừa tạo, kiểm tra quyền admin

#### TC_SEC_INJ_02 — GDPR Deleted Account Access
- **Mục tiêu:** Khai thác SQLi để truy cập tài khoản đã bị xóa (GDPR)
- **Endpoint:** `POST /rest/user/login`
- **Payload:** `{"email": "' OR DeletedAt IS NOT NULL --", "password": "x"}`
- **Các bước thủ công:**
  1. Quan sát lỗi SQL khi nhập `'` vào email field
  2. Phân tích lỗi SQL để thấy query kiểm tra `DeletedAt`
  3. Inject payload để login vào tài khoản có `DeletedAt IS NOT NULL`

#### TC_SEC_INJ_03 — Ephemeral Accountant (UNION SELECT)
- **Mục tiêu:** Dùng UNION SELECT SQLi để tạo user ảo trong bộ nhớ
- **Endpoint:** `POST /rest/user/login`
- **Payload:** UNION SELECT fabricating user `acc0unt4nt@juice-sh.op`
- **Các bước thủ công:**
  1. Bắt request login
  2. Thay email bằng UNION SELECT injection
  3. Kiểm tra server trả về JWT cho user không tồn tại

#### TC_SEC_INJ_04 — SSTI Malware Execution (Pug Template Injection)
- **Mục tiêu:** Khai thác Server-Side Template Injection trong Pug để RCE
- **Endpoint:** `PUT /api/Users/1`
- **Payload:** `{"username": "#{global.process.mainModule.require('child_process').execSync('id').toString()}"}`
- **Các bước thủ công:**
  1. Đăng nhập với tài khoản user
  2. Vào profile page, sửa username field
  3. Inject payload SSTI vào username
  4. Kiểm tra kết quả evaluated expression

#### TC_SEC_AUTH_01 — OAuth Password Reverse Engineering
- **Mục tiêu:** Đảo ngược thuật toán tạo password cho user OAuth
- **Endpoint:** `POST /rest/user/login`
- **Payload:** Email `bjoern.kimmich@gmail.com`, password = Base64(reverse(email))
- **Các bước thủ công:**
  1. Phân tích main.js tìm hàm xử lý OAuth login
  2. Xác định thuật toán password: reverse email → Base64 encode
  3. Áp dụng cho email Bjoern
  4. Login với email và password đã tính

#### TC_SEC_AUTH_02 — TOTP 2FA Bypass via SQLi
- **Mục tiêu:** Trích xuất TOTP secret qua SQLi trong search để bypass 2FA
- **Endpoint:** `GET /rest/products/search?q=`
- **Payload:** UNION SELECT extracting `totpSecret` từ bảng USERS
- **Các bước thủ công:**
  1. Dùng SQLi trong search feature
  2. UNION SELECT thêm cột `totpSecret`
  3. Dùng secret để tạo TOTP code hợp lệ
  4. Nhập code tại 2FA prompt

#### TC_SEC_AUTH_03 — JWT 'none' Algorithm
- **Mục tiêu:** Kiểm tra server có chấp nhận JWT với alg='none' không
- **Endpoint:** `GET /rest/user/whoami`
- **Payload:** JWT với header `{"alg": "none"}`, email `jwtn3d@juice-sh.op`
- **Các bước thủ công:**
  1. Decode JWT template
  2. Sửa header `alg` thành `none`
  3. Sửa payload email
  4. Concatenate header.payload. với empty signature
  5. Gửi request với token đã forge

#### TC_SEC_AUTH_04 — JWT RS256→HS256 Algorithm Confusion
- **Mục tiêu:** Chuyển JWT từ RS256 sang HS256, ký với public key
- **Endpoint:** `GET /rest/user/whoami`
- **Payload:** JWT với HS256, ký bằng public key từ `/encryptionkeys/jwt.pub`
- **Các bước thủ công:**
  1. Lấy public key từ `/encryptionkeys/jwt.pub`
  2. Sửa JWT header `alg` thành `HS256`
  3. Ký JWT với public key làm HMAC secret
  4. Gửi request

#### TC_SEC_SDE_01 — FTP Confidential Document
- **Mục tiêu:** Tài liệu mật trên FTP server không cần xác thực
- **Endpoint:** `GET /ftp/acquisition.md`
- **Các bước thủ công:**
  1. Vào `/ftp` directory
  2. Tìm file `acquisition.md`
  3. Download và mở
  4. Xác nhận nội dung nhạy cảm

#### TC_SEC_SDE_02 — GPS EXIF Password Reset
- **Mục tiêu:** Dùng GPS metadata trong ảnh để reset password người khác
- **Endpoint:** `GET /assets/public/images/uploads/favorite-hiking-place.png`
- **Các bước thủ công:**
  1. Vào photo wall, tìm ảnh `favorite-hiking-place.png`
  2. Download ảnh, dùng ExifTool trích xuất GPS metadata
  3. Tra tọa độ (36°57'31.38"N 84°20'53.58"W) → Daniel Boone National Forest
  4. Dùng đáp án đó để reset password của John

#### TC_SEC_XSS_01 — DOM XSS iframe Injection
- **Mục tiêu:** Kiểm tra search parameter có bị DOM XSS không
- **Endpoint:** `GET /#/search?q=<iframe...>`
- **Payload:** iframe SoundCloud player trong `q` parameter
- **Các bước thủ công:**
  1. Tạo iframe payload
  2. URL-encode
  3. Inject vào search query
  4. Quan sát iframe render trong DOM

---

## 5. Xem và Hiểu Báo Cáo (Viewing the Report)

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

## 6. Dọn Dẹp và Chạy Lại (Re-running)

Trong quá trình bạn sửa lỗi trên backend và muốn quét lại để kiểm tra xem lỗi đã hết chưa, bạn có thể xóa các báo cáo cũ đi cho đỡ rối, sau đó chạy lại lệnh quét:

* **Xóa báo cáo cũ (Trên PowerShell):**
  ```powershell
  Remove-Item -Path "reports\*" -Recurse -Force
  ```
* **Chạy lại:**
  ```bash
  python -m websec_test.main --target http://localhost:8080/note/login --all --dashboard
  ```
* **Chạy lại test Juice Shop:**
  ```bash
  python -m pytest tests/test_pentestgpt_auto.py -v --integration
  ```

---

## 7. Lưu Đồ Quy Trình Kiểm Thử (Testing Workflow)

```
┌─────────────────────────────────────────────────────────────┐
│              OWASP Juice Shop (Docker Container)             │
│              http://localhost:3000                            │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP Requests
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              PentestGPT Pipeline (test_pentestgpt_auto.py)    │
│                                                              │
│  1. Gửi context test case → PentestGPT LLM                   │
│  2. LLM trả về TYPE: HTTP hoặc TYPE: SCRIPT                  │
│  3. Thực thi request/script lên Juice Shop                    │
│  4. Gửi kết quả lại LLM để đánh giá PASS/FAIL                │
│  5. Ghi log ra JSON report                                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Ollama (qwen2.5-coder:7b)                       │
│              Local LLM for security reasoning                 │
└─────────────────────────────────────────────────────────────┘
```
