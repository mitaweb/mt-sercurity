# MT Security

Bộ plugin bảo mật toàn diện, **nhẹ và nhanh** cho WordPress. Tự triển khai, không phụ thuộc dịch vụ ngoài, tối ưu để **không làm chậm website**.

## Tính năng

| # | Tính năng | Mô tả |
|---|-----------|-------|
| 1 | 🔥 **Tường lửa (WAF)** | Chặn SQL Injection, XSS, Path Traversal/LFI, truy cập file nhạy cảm (`.env`, `.git`, `wp-config.php`), bot quét lỗ hổng (sqlmap, wpscan, nikto…). |
| 2 | 🔒 **Chống brute-force** | Đăng nhập sai N lần (mặc định 3) → khóa IP; tái phạm khóa lâu hơn. |
| 3 | 🔐 **Đăng nhập 2 lớp (2FA)** | App xác thực **TOTP** (Google Authenticator/Authy, chuẩn RFC 6238) hoặc **OTP email**, kèm **mã dự phòng** dùng một lần. |
| 4 | 🚪 **Đổi đường dẫn đăng nhập** | Ẩn `wp-login.php` & `/wp-admin` với khách, chỉ vào qua slug tùy chỉnh. |
| 5 | 🛡️ **Gia cố hệ thống** | Ẩn version WP, tắt XML-RPC & Pingback, chặn dò username, ẩn user REST API, cấm sửa file, chặn `readme.html`/`license.txt`. |
| 6 | 💬 **Chống spam bình luận** | Honeypot, kiểm tra thời gian gửi, giới hạn số link, lọc từ khóa. |
| 7 | 👤 **Bảo vệ tài khoản** | Chặn đăng ký mới, **phát hiện tài khoản admin ẩn** (dò thẳng trong DB), cảnh báo email khi có admin mới, tùy chọn tự hạ quyền admin lạ. |

## Tối ưu tốc độ

- Trang quản trị chỉ nạp trong `wp-admin`, không đụng front-end.
- Tường lửa dừng sớm với request sạch; quét sâu hoãn tới `init` và bỏ qua user có quyền biên tập.
- Dùng transient (tận dụng Redis/Memcached nếu có), không ghi log file mỗi request.
- Không thêm CSS/JS ở front-end.

## Cài đặt

1. Tải file `mt-security.zip` (hoặc tải repo dạng ZIP).
2. Vào **Plugins → Add New → Upload Plugin**, chọn file zip.
3. Kích hoạt, rồi vào menu **MT Security** để cấu hình.

Hoặc dùng git:

```bash
git clone https://github.com/mitaweb/mt-sercurity.git
# copy thư mục mt-security/ vào wp-content/plugins/
```

## ⚠️ Lưu ý quan trọng

- **Đổi đường dẫn đăng nhập**: ghi nhớ slug mới **trước khi đăng xuất**.
- **Chặn đăng ký**: nếu web dùng WooCommerce/thành viên cho khách tự đăng ký → hãy tắt mục này.
- **2FA TOTP**: mỗi admin tự thiết lập trong **Users → Hồ sơ**; nhớ lưu mã dự phòng.
- **Công tắc khẩn cấp**: nếu lỡ tự khóa, thêm vào `wp-config.php`:
  ```php
  define('MT_SEC_DISABLE', true);
  ```

## License

GPL-2.0+
