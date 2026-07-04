<?php
/**
 * Tường lửa ứng dụng web (WAF) đơn giản, tối ưu tốc độ.
 *
 * Triết lý: chạy CỰC SỚM, kiểm tra RẺ trước (user-agent, file nhạy cảm),
 * chỉ chạy regex nặng khi request có dấu hiệu nghi ngờ (có query string).
 * Bỏ qua hoàn toàn user đã đăng nhập là quản trị để không cản trở thao tác.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Firewall {

	/**
	 * Cấu hình.
	 *
	 * @var array
	 */
	private $s;

	/**
	 * Constructor.
	 *
	 * @param array $settings Cấu hình.
	 */
	public function __construct( $settings ) {
		$this->s = $settings;
	}

	/**
	 * Chạy kiểm tra.
	 */
	public function run() {
		// Bỏ qua CLI / cron để không ảnh hưởng tác vụ nền.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ip = MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) );

		// IP trong whitelist -> bỏ qua tường lửa.
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( $_SERVER['REQUEST_URI'] ) : '';
		$qs  = isset( $_SERVER['QUERY_STRING'] ) ? rawurldecode( $_SERVER['QUERY_STRING'] ) : '';
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';

		// 1) Chặn user-agent xấu (rẻ nhất).
		if ( ! empty( $this->s['fw_block_bad_agents'] ) && $this->bad_user_agent( $ua ) ) {
			$this->block( 'bad_user_agent' );
		}

		// 2) Bảo vệ file nhạy cảm.
		if ( ! empty( $this->s['fw_protect_files'] ) && $this->hit_sensitive_file( $uri ) ) {
			$this->block( 'sensitive_file' );
		}

		// Nếu không có query string và không có POST -> request sạch, dừng sớm.
		$has_payload = ( '' !== $qs ) || ! empty( $_POST );
		if ( ! $has_payload ) {
			return;
		}

		// Quét sâu (SQLi/XSS) hoãn tới 'init' để biết được user đăng nhập,
		// tránh chặn nhầm khi admin/editor lưu nội dung hợp lệ (chứa <script>, code...).
		add_action( 'init', array( $this, 'deep_scan' ), 0 );
	}

	/**
	 * Quét sâu payload. Bỏ qua người dùng có quyền biên tập.
	 */
	public function deep_scan() {
		// Người đăng nhập có quyền đăng bài -> tin tưởng, không quét (tránh false-positive khi soạn thảo).
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return;
		}

		$qs = isset( $_SERVER['QUERY_STRING'] ) ? rawurldecode( $_SERVER['QUERY_STRING'] ) : '';

		// Gộp dữ liệu cần soi (bỏ qua trường mật khẩu để không chặn nhầm khi đăng nhập).
		$skip     = array( 'pwd', 'pass', 'pass1', 'pass2', 'user_pass', 'password' );
		$haystack = $qs;
		if ( ! empty( $_POST ) ) {
			$haystack .= ' ' . $this->flatten( array_diff_key( $_POST, array_flip( $skip ) ) );
		}
		if ( ! empty( $_GET ) ) {
			$haystack .= ' ' . $this->flatten( $_GET );
		}
		$haystack = strtolower( $haystack );

		if ( ! empty( $this->s['fw_block_sqli'] ) && $this->match_sqli( $haystack ) ) {
			$this->block( 'sqli' );
		}
		if ( ! empty( $this->s['fw_block_xss'] ) && $this->match_xss( $haystack ) ) {
			$this->block( 'xss_lfi' );
		}
	}

	/**
	 * IP có trong whitelist?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		if ( empty( $this->s['fw_whitelist_ips'] ) ) {
			return false;
		}
		$list = preg_split( '/[\r\n,]+/', $this->s['fw_whitelist_ips'] );
		foreach ( $list as $entry ) {
			$entry = trim( $entry );
			if ( '' !== $entry && $entry === $ip ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * User-agent độc hại / rỗng đáng ngờ.
	 *
	 * @param string $ua User agent.
	 * @return bool
	 */
	private function bad_user_agent( $ua ) {
		if ( '' === $ua ) {
			return false; // Không chặn UA rỗng để tránh chặn nhầm trình kiểm tra/uptime.
		}
		$bad = array( 'sqlmap', 'nikto', 'fimap', 'nessus', 'whatweb', 'nmap', 'masscan', 'zgrab', 'libwww-perl', 'wpscan', 'havij', 'acunetix', 'netsparker', 'dirbuster' );
		$ua  = strtolower( $ua );
		foreach ( $bad as $needle ) {
			if ( false !== strpos( $ua, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Truy cập file/đường dẫn nhạy cảm.
	 *
	 * @param string $uri URI.
	 * @return bool
	 */
	private function hit_sensitive_file( $uri ) {
		$uri = strtolower( $uri );
		$bad = array( '/.env', '/.git/', '/wp-config.php', '/wp-config.bak', '.sql', '/.htaccess', '/.aws/', '/.ssh/', 'wlwmanifest.xml' );
		foreach ( $bad as $needle ) {
			if ( false !== strpos( $uri, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Dấu hiệu SQL Injection.
	 *
	 * @param string $h Haystack đã lowercase.
	 * @return bool
	 */
	private function match_sqli( $h ) {
		// Mẫu thường gặp, hạn chế false-positive.
		$patterns = array(
			'/union(\s|\/\*.*?\*\/|\+)+select/i',
			'/\b(select|insert|update|delete)\b.+\b(from|into|where)\b.+(--|#|;)/i',
			'/(\%27|\')\s*(or|and)\s*[\'"\d]/i',
			'/\bor\b\s+1\s*=\s*1/i',
			'/information_schema/i',
			'/\bsleep\s*\(\s*\d+\s*\)/i',
			'/\bbenchmark\s*\(/i',
			'/load_file\s*\(/i',
			'/\bconcat\s*\(.*select/i',
		);
		foreach ( $patterns as $p ) {
			if ( preg_match( $p, $h ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Dấu hiệu XSS / LFI / RCE.
	 *
	 * @param string $h Haystack đã lowercase.
	 * @return bool
	 */
	private function match_xss( $h ) {
		$patterns = array(
			'/<script\b/i',
			'/javascript:/i',
			'/onerror\s*=/i',
			'/onload\s*=/i',
			'/document\.cookie/i',
			'/\.\.\/\.\.\//',                 // Path traversal.
			'/(etc\/passwd|proc\/self\/environ)/i',
			'/php:\/\/(input|filter)/i',
			'/base64_decode\s*\(/i',
			'/\$\{.*\}/',                     // Một số dạng template/RCE.
		);
		foreach ( $patterns as $p ) {
			if ( preg_match( $p, $h ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Làm phẳng mảng thành chuỗi (giới hạn độ sâu để tránh tốn CPU).
	 *
	 * @param array $arr   Mảng đầu vào.
	 * @param int   $depth Độ sâu hiện tại.
	 * @return string
	 */
	private function flatten( $arr, $depth = 0 ) {
		if ( $depth > 3 || ! is_array( $arr ) ) {
			return is_scalar( $arr ) ? (string) $arr : '';
		}
		$out = '';
		foreach ( $arr as $v ) {
			if ( is_array( $v ) ) {
				$out .= ' ' . $this->flatten( $v, $depth + 1 );
			} elseif ( is_scalar( $v ) ) {
				$out .= ' ' . $v;
			}
		}
		return $out;
	}

	/**
	 * Chặn request và dừng.
	 *
	 * @param string $reason Lý do (để log).
	 */
	private function block( $reason ) {
		$this->bump_blocked();

		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		// Phản hồi tối giản, không lộ thông tin.
		echo '403 Forbidden';
		exit;
	}

	/**
	 * Tăng bộ đếm request đã chặn — có tiết chế ghi DB.
	 *
	 * Cộng dồn trong object cache; chỉ ghi xuống DB tối đa ~1 lần/60s để tránh
	 * khuếch đại lượt GHI khi bị tấn công dồn dập (mỗi request xấu = 1 write).
	 * Với site có object cache bền (Redis/Memcached) số đếm vẫn chính xác;
	 * không có cache bền thì chấp nhận sai số nhỏ, đổi lấy việc không spam ghi DB.
	 */
	private function bump_blocked() {
		$pending = (int) wp_cache_get( 'fw_pending', 'mt_sec' ) + 1;
		wp_cache_set( 'fw_pending', $pending, 'mt_sec' );

		// Khóa tiết chế: còn hiệu lực -> chưa ghi DB.
		if ( get_transient( 'mt_sec_fw_wlock' ) ) {
			return;
		}
		set_transient( 'mt_sec_fw_wlock', 1, MINUTE_IN_SECONDS );
		wp_cache_set( 'fw_pending', 0, 'mt_sec' );

		$count = (int) get_option( 'mt_sec_fw_blocked', 0 );
		update_option( 'mt_sec_fw_blocked', $count + $pending, false );
	}
}
