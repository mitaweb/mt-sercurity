=== MT Security ===
Contributors: MT
Tags: security, firewall, 2fa, anti-spam, brute force, hide login, xmlrpc
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later

Bộ bảo mật toàn diện, nhẹ và nhanh cho WordPress.

== Tính năng ==

1. **Tường lửa (WAF)** – Chặn SQL Injection, XSS, Path Traversal/LFI, truy cập file nhạy cảm (.env, .git, wp-config.php), và bot quét lỗ hổng (sqlmap, nikto, wpscan...). Chạy cực sớm, kiểm tra rẻ trước, chỉ soi sâu khi request có dấu hiệu nghi ngờ.
2. **Chống brute-force** – Sai mật khẩu N lần (mặc định 3) sẽ khóa IP theo thời gian; tái phạm bị khóa dài hơn.
3. **Đăng nhập 2 lớp (2FA)** – Hai phương thức: **app xác thực (TOTP)** như Google Authenticator/Authy (chuẩn RFC 6238, tự triển khai, không phụ thuộc thư viện ngoài) hoặc **mã OTP qua email**. Kèm **mã dự phòng (backup codes)** dùng một lần khi mất thiết bị. Áp dụng theo vai trò.
4. **Đổi đường dẫn đăng nhập** – Ẩn wp-login.php và /wp-admin với khách, chỉ vào được qua slug tùy chỉnh.
5. **Gia cố hệ thống** – Ẩn version WP, tắt XML-RPC & Pingback, gỡ X-Pingback, chặn dò username, ẩn user REST API, cấm sửa file, chặn readme/license.
6. **Chống spam bình luận** – Honeypot, kiểm tra thời gian gửi, giới hạn số link, lọc từ khóa. Không gọi dịch vụ ngoài.
7. **Bảo vệ tài khoản (User Guard)** – Chặn tạo tài khoản mới (tắt đăng ký công khai), phát hiện **tài khoản quản trị ẩn** do malware tạo (dò thẳng trong DB), cảnh báo email khi có admin mới, và tùy chọn tự hạ quyền admin lạ.

== Tối ưu tốc độ ==

* Module quản trị chỉ nạp trong wp-admin.
* Tường lửa dừng sớm với request sạch (không query string, không POST).
* Dùng transient (tận dụng object cache như Redis/Memcached nếu có).
* Không ghi log ra file ở mỗi request; chỉ tăng bộ đếm dạng option.
* Không thêm CSS/JS ở front-end.

== Cài đặt ==

1. Chép thư mục `mt-security` vào `wp-content/plugins/`.
2. Kích hoạt plugin trong **Plugins**.
3. Vào menu **MT Security** để cấu hình.

== Lưu ý quan trọng ==

* **Đổi đường dẫn đăng nhập**: Ghi nhớ slug mới TRƯỚC khi đăng xuất. Nếu quên, tắt plugin bằng cách đổi tên thư mục plugin qua FTP/File Manager.
* **2FA qua email**: Chỉ bật khi chắc chắn website gửi được email (nên cài SMTP). Nếu email không tới, dùng FTP đặt biến `define('MT_SEC_DISABLE','1')` hoặc tắt plugin để vào lại.
* Nếu dùng Cloudflare/Proxy, bật tùy chọn "Đang dùng Cloudflare/Proxy tin cậy" để lấy đúng IP và whitelist IP của bạn.

== Changelog ==

= 1.0.2 =
* Tối ưu hiệu năng: bỏ 1 truy vấn DB thừa trên MỖI request (baseline admin của User Guard nay khởi tạo lúc kích hoạt + lazy khi cần).
* Tối ưu admin: cache cờ cảnh báo "admin ẩn/chưa duyệt" (transient 12h) thay vì quét usermeta trên mọi trang admin; tự làm mới khi có thay đổi.
* Tường lửa: tiết chế ghi DB bộ đếm (cộng dồn object cache, ghi tối đa ~1 lần/60s) để tránh khuếch đại ghi khi bị tấn công dồn dập.
* Ẩn version: chỉ gỡ ?ver của asset WP core, giữ cache-busting cho theme/plugin.
* Vi chỉnh: chỉ đăng ký hook hồ sơ/thông báo của 2FA trong khu vực admin.

= 1.0.1 =
* Sửa lỗi: khi bật "Đổi đường dẫn đăng nhập", đường dẫn mới báo 404. Nguyên nhân do hook can thiệp login đăng ký sai thời điểm (plugins_loaded đã chạy qua) và require wp-login.php trước khi pluggable.php nạp. Nay chuyển sang hook wp_loaded và nạp module sớm trong constructor.
* Chặn khách vào /wp-admin trả về 404 (thay vì bị đá về trang đăng nhập), xử lý ở hook init.
* Trang 404 fallback gọn gàng hơn.

= 1.0.0 =
* Phát hành lần đầu.
