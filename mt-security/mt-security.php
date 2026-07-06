<?php
/**
 * Plugin Name:       MT Security
 * Plugin URI:        https://example.com/mt-security
 * Description:        Bộ bảo mật toàn diện cho WordPress: chống spam bình luận, đăng nhập 2 lớp (2FA), tắt XML-RPC, ẩn phiên bản WP, đổi đường dẫn đăng nhập, khóa IP khi đăng nhập sai, và tường lửa (WAF). Tối ưu tốc độ, không làm chậm website.
 * Version:           1.0.3
 * Requires at least: 5.0
 * Requires PHP:      7.2
 * Author:            MT
 * License:           GPL-2.0+
 * Text Domain:       mt-security
 * Domain Path:       /languages
 *
 * @package MT_Security
 */

// Chặn truy cập trực tiếp.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ----- Hằng số -----
define( 'MT_SEC_VERSION', '1.0.3' );
define( 'MT_SEC_FILE', __FILE__ );
define( 'MT_SEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'MT_SEC_URL', plugin_dir_url( __FILE__ ) );
define( 'MT_SEC_BASENAME', plugin_basename( __FILE__ ) );
define( 'MT_SEC_OPTION', 'mt_security_settings' );

// ----- Nạp lớp chính -----
require_once MT_SEC_DIR . 'includes/class-mt-security.php';

/**
 * Lấy instance chính (singleton).
 *
 * @return MT_Security
 */
function mt_security() {
	return MT_Security::instance();
}

// Khởi động sớm để Tường lửa có thể chặn request độc hại trước khi WP load nặng.
mt_security();

// ----- Kích hoạt / Hủy kích hoạt -----
register_activation_hook( __FILE__, array( 'MT_Security', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'MT_Security', 'deactivate' ) );
