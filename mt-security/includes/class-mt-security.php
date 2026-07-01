<?php
/**
 * Lớp điều phối chính của MT Security.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class MT_Security {

	/**
	 * Instance singleton.
	 *
	 * @var MT_Security|null
	 */
	private static $instance = null;

	/**
	 * Cấu hình đã nạp.
	 *
	 * @var array
	 */
	private $settings = array();

	/**
	 * Lấy instance.
	 *
	 * @return MT_Security
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->settings = $this->get_settings();

		// Công tắc khẩn cấp: thêm define('MT_SEC_DISABLE', true); vào wp-config.php
		// để tạm tắt mọi tính năng bảo mật (dùng khi lỡ tự khóa mình).
		if ( defined( 'MT_SEC_DISABLE' ) && MT_SEC_DISABLE ) {
			add_action( 'init', array( $this, 'load_textdomain' ) );
			if ( is_admin() ) {
				add_action( 'plugins_loaded', array( $this, 'load_admin_only' ) );
			}
			return;
		}

		// Tường lửa chạy CỰC SỚM (trước khi WP nạp theme/plugin nặng) để chặn request xấu rẻ nhất.
		if ( $this->enabled( 'firewall' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-firewall.php';
			( new MT_Sec_Firewall( $this->settings ) )->run();
		}

		// Đổi đường dẫn đăng nhập PHẢI nạp sớm (trước khi 'plugins_loaded' kích hoạt)
		// để hook can thiệp login chạy đúng, nếu không slug mới sẽ bị 404.
		if ( $this->enabled( 'custom_login' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-login-url.php';
			( new MT_Sec_Login_Url( $this->settings ) )->run();
		}

		// Phần còn lại nạp khi WP đã sẵn sàng.
		add_action( 'plugins_loaded', array( $this, 'load_modules' ) );
		add_action( 'init', array( $this, 'load_textdomain' ) );
	}

	/**
	 * Nạp các module theo cấu hình.
	 */
	public function load_modules() {
		// Gia cố hệ thống: ẩn version, tắt xmlrpc, chặn dò user...
		if ( $this->enabled( 'hardening' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-hardening.php';
			( new MT_Sec_Hardening( $this->settings ) )->run();
		}

		// Chống spam bình luận (chỉ cần ở front-end + khi gửi comment).
		if ( $this->enabled( 'antispam' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-antispam.php';
			( new MT_Sec_Antispam( $this->settings ) )->run();
		}

		// Giới hạn đăng nhập sai / khóa IP.
		if ( $this->enabled( 'brute_force' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-bruteforce.php';
			( new MT_Sec_Bruteforce( $this->settings ) )->run();
		}

		// Lưu ý: module "Đổi đường dẫn đăng nhập" đã được nạp sớm trong constructor.

		// Đăng nhập 2 lớp (2FA).
		if ( $this->enabled( 'two_factor' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-2fa.php';
			( new MT_Sec_Two_Factor( $this->settings ) )->run();
		}

		// Bảo vệ tài khoản: chặn đăng ký mới & phát hiện admin ẩn.
		if ( $this->enabled( 'user_guard' ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-user-guard.php';
			( new MT_Sec_User_Guard( $this->settings ) )->run();
		}

		// Trang quản trị chỉ nạp trong admin -> không ảnh hưởng tốc độ front-end.
		if ( is_admin() ) {
			require_once MT_SEC_DIR . 'includes/class-mt-admin.php';
			( new MT_Sec_Admin( $this->settings ) )->run();
		}
	}

	/**
	 * Chỉ nạp trang quản trị (dùng ở chế độ khẩn cấp).
	 */
	public function load_admin_only() {
		require_once MT_SEC_DIR . 'includes/class-mt-admin.php';
		( new MT_Sec_Admin( $this->settings ) )->run();
	}

	/**
	 * Nạp bản dịch.
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'mt-security', false, dirname( MT_SEC_BASENAME ) . '/languages' );
	}

	/**
	 * Cấu hình mặc định.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			// Bật/tắt module.
			'firewall'              => 1,
			'hardening'             => 1,
			'antispam'              => 1,
			'brute_force'           => 1,
			'custom_login'          => 0, // Mặc định TẮT để tránh người dùng tự khóa mình; bật trong cài đặt.
			'two_factor'            => 0, // Mặc định TẮT; bật khi đã cấu hình email gửi được.
			'user_guard'            => 1,

			// Gia cố.
			'hide_wp_version'       => 1,
			'disable_xmlrpc'        => 1,
			'disable_file_edit'     => 1,
			'block_user_enum'       => 1,
			'disable_rest_users'    => 1,
			'remove_readme'         => 1,

			// Chống spam.
			'spam_honeypot'         => 1,
			'spam_min_time'         => 4,    // Giây tối thiểu để điền form.
			'spam_max_links'        => 2,    // Số link tối đa trong bình luận.
			'spam_block_keywords'   => 1,
			'spam_keywords'         => "viagra\ncasino\nporn\nxxx\ncialis\nبكام\n[url=",

			// Brute force.
			'bf_max_attempts'       => 3,    // Sai 3 lần.
			'bf_lockout_minutes'    => 30,   // Khóa 30 phút.
			'bf_long_lockout'       => 24,   // Khóa dài (giờ) nếu tái phạm nhiều.
			'bf_long_threshold'     => 3,    // Số lần bị khóa trước khi khóa dài.

			// Đổi đường dẫn login.
			'login_slug'            => 'secure-login',

			// 2FA.
			'2fa_roles'             => array( 'administrator', 'editor' ),
			'2fa_code_ttl'          => 10,   // Phút hiệu lực mã OTP (email).
			'2fa_method'            => 'totp', // 'totp' (app xác thực) hoặc 'email'.
			'2fa_backup_count'      => 10,   // Số mã dự phòng cấp cho mỗi user.

			// Bảo vệ tài khoản (User Guard).
			'block_registration'    => 1,
			'guard_admins'          => 1,
			'block_new_admins'      => 0,    // Chặn cứng: hạ quyền admin lạ ngay lập tức.
			'guard_alert_email'     => '',   // Rỗng = dùng admin_email.

			// Tường lửa.
			'fw_block_bad_agents'   => 1,
			'fw_block_sqli'         => 1,
			'fw_block_xss'          => 1,
			'fw_protect_files'      => 1,
			'fw_trust_proxy'        => 0,    // Bật nếu dùng Cloudflare/Proxy đáng tin.
			'fw_whitelist_ips'      => '',   // Danh sách IP tin cậy, mỗi dòng 1 IP.
		);
	}

	/**
	 * Lấy cấu hình (merge với mặc định).
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( ! empty( $this->settings ) ) {
			return $this->settings;
		}
		$saved          = get_option( MT_SEC_OPTION, array() );
		$this->settings = wp_parse_args( is_array( $saved ) ? $saved : array(), self::default_settings() );
		return $this->settings;
	}

	/**
	 * Kiểm tra một module/tùy chọn có bật không.
	 *
	 * @param string $key Khóa cấu hình.
	 * @return bool
	 */
	public function enabled( $key ) {
		return ! empty( $this->settings[ $key ] );
	}

	/**
	 * Lấy IP thật của khách (an toàn trước giả mạo).
	 *
	 * @param bool $trust_proxy Có tin header proxy không.
	 * @return string
	 */
	public static function get_ip( $trust_proxy = false ) {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

		if ( $trust_proxy ) {
			// Chỉ dùng khi thật sự đứng sau proxy tin cậy (Cloudflare...).
			$candidates = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' );
			foreach ( $candidates as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
					$parts = explode( ',', $_SERVER[ $h ] );
					$maybe = trim( $parts[0] );
					if ( filter_var( $maybe, FILTER_VALIDATE_IP ) ) {
						$ip = $maybe;
						break;
					}
				}
			}
		}

		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	/**
	 * Kích hoạt plugin.
	 */
	public static function activate() {
		// Lưu cấu hình mặc định nếu chưa có.
		if ( false === get_option( MT_SEC_OPTION ) ) {
			add_option( MT_SEC_OPTION, self::default_settings() );
		}

		// Nạp module login url để đăng ký rewrite rồi flush.
		$settings = get_option( MT_SEC_OPTION, self::default_settings() );
		if ( ! empty( $settings['custom_login'] ) ) {
			require_once MT_SEC_DIR . 'includes/class-mt-login-url.php';
			( new MT_Sec_Login_Url( $settings ) )->run();
		}
		flush_rewrite_rules();
	}

	/**
	 * Hủy kích hoạt plugin.
	 */
	public static function deactivate() {
		flush_rewrite_rules();
	}
}
