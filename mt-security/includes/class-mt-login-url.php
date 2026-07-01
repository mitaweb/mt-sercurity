<?php
/**
 * Đổi đường dẫn đăng nhập (ẩn wp-login.php).
 * Cách tiếp cận an toàn: chặn truy cập wp-login.php & /wp-admin của khách,
 * chỉ cho vào qua slug tùy chỉnh.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Login_Url {

	/**
	 * Cấu hình.
	 *
	 * @var array
	 */
	private $s;

	/**
	 * Slug đăng nhập.
	 *
	 * @var string
	 */
	private $slug;

	/**
	 * Constructor.
	 *
	 * @param array $settings Cấu hình.
	 */
	public function __construct( $settings ) {
		$this->s    = $settings;
		$slug       = isset( $settings['login_slug'] ) ? sanitize_title( $settings['login_slug'] ) : 'secure-login';
		$this->slug = $slug ? $slug : 'secure-login';
	}

	/**
	 * Chạy module.
	 */
	public function run() {
		// Dùng 'wp_loaded': WP đã nạp đủ (gồm pluggable.php) nên require wp-login.php an toàn,
		// nhưng vẫn chạy TRƯỚC khi WordPress định tuyến & quyết định 404.
		add_action( 'wp_loaded', array( $this, 'intercept' ), 1 );
		// Chặn khách vào /wp-admin -> đặt ở 'init' để hàm is_user_logged_in() sẵn sàng.
		add_action( 'init', array( $this, 'block_admin' ), 0 );
		add_filter( 'site_url', array( $this, 'filter_login_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'filter_login_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'filter_redirect' ), 10, 2 );
		add_filter( 'login_url', array( $this, 'login_url' ), 10, 3 );
		add_filter( 'logout_url', array( $this, 'logout_url' ), 10, 2 );
		add_filter( 'lostpassword_url', array( $this, 'login_url' ), 10, 3 );
	}

	/**
	 * Lấy đường dẫn yêu cầu (path).
	 *
	 * @return string
	 */
	private function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		$home = wp_parse_url( home_url(), PHP_URL_PATH );
		$path = untrailingslashit( $path );
		if ( $home && '/' !== $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		return trim( $path, '/' );
	}

	/**
	 * Can thiệp luồng đăng nhập sớm.
	 */
	public function intercept() {
		$path = $this->request_path();

		$is_wplogin = ( false !== strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) );

		// 1) Truy cập đúng slug -> tải wp-login.php.
		if ( $path === $this->slug ) {
			// Đặt cờ để các filter biết ta đang ở trang đăng nhập hợp lệ.
			$GLOBALS['mt_sec_login_ok'] = true;
			require_once ABSPATH . 'wp-login.php';
			exit;
		}

		// 2) Truy cập trực tiếp wp-login.php -> trả 404 (ẩn).
		if ( $is_wplogin && empty( $GLOBALS['mt_sec_login_ok'] ) ) {
			// Cho phép logout/postpass/luồng nội bộ POST hợp lệ đi qua action an toàn.
			$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : '';
			$allowed_actions = array( 'logout', 'postpass', 'rp', 'resetpass', 'confirmaction' );
			if ( in_array( $action, $allowed_actions, true ) ) {
				return;
			}
			$this->deny();
		}
	}

	/**
	 * Chặn khách (chưa đăng nhập) truy cập /wp-admin -> 404.
	 * Chạy ở 'init' (trước auth_redirect của wp-admin) nên khách bị 404 thay vì bị đá về trang login.
	 */
	public function block_admin() {
		if ( ! is_admin() ) {
			return; // Chỉ xử lý khu vực quản trị.
		}
		// Cho phép các endpoint hợp lệ mà front-end cần gọi.
		if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		if ( false !== strpos( $uri, 'admin-ajax.php' ) || false !== strpos( $uri, 'admin-post.php' ) ) {
			return;
		}
		if ( is_user_logged_in() ) {
			return; // Đã đăng nhập -> vào bình thường.
		}
		$this->deny();
	}

	/**
	 * Trả về 404 không lộ thông tin.
	 */
	private function deny() {
		if ( ! headers_sent() ) {
			status_header( 404 );
			nocache_headers();
		}

		global $wp_query;

		// Front-end: cố dùng template 404 của theme cho tự nhiên (khi WP đã sẵn sàng).
		if ( ! is_admin() && did_action( 'template_redirect' ) === 0 && function_exists( 'get_query_template' ) ) {
			if ( $wp_query ) {
				$wp_query->set_404();
			}
			$tpl = get_query_template( '404' );
			if ( $tpl && file_exists( $tpl ) ) {
				include $tpl;
				exit;
			}
		}

		// Fallback tối giản (khu vực admin hoặc theme không có 404.php).
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>404 Not Found</title>';
		echo '<style>body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7f7;color:#3c434a;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.b{text-align:center}.c{font-size:64px;font-weight:700;margin:0;color:#1d2327}p{font-size:15px;color:#646970}</style>';
		echo '</head><body><div class="b"><p class="c">404</p><p>' . esc_html__( 'Không tìm thấy trang bạn yêu cầu.', 'mt-security' ) . '</p></div></body></html>';
		exit;
	}

	/**
	 * Thay wp-login.php bằng slug trong site_url.
	 *
	 * @param string $url     URL.
	 * @param string $path    Path.
	 * @param string $scheme  Scheme.
	 * @param int    $blog_id Blog ID.
	 * @return string
	 */
	public function filter_login_url( $url, $path, $scheme = null, $blog_id = null ) {
		if ( is_string( $path ) && false !== strpos( $path, 'wp-login.php' ) ) {
			$url = str_replace( 'wp-login.php', $this->slug, $url );
		}
		return $url;
	}

	/**
	 * Đổi URL redirect chứa wp-login.php.
	 *
	 * @param string $location URL.
	 * @param int    $status   Mã trạng thái.
	 * @return string
	 */
	public function filter_redirect( $location, $status = 302 ) {
		if ( false !== strpos( $location, 'wp-login.php' ) && false === strpos( $location, 'action=logout' ) ) {
			$location = str_replace( 'wp-login.php', $this->slug, $location );
		}
		return $location;
	}

	/**
	 * login_url filter.
	 *
	 * @param string $login_url   URL.
	 * @param string $redirect    Redirect.
	 * @param bool   $force_reauth Reauth.
	 * @return string
	 */
	public function login_url( $login_url, $redirect = '', $force_reauth = false ) {
		$url = home_url( $this->slug . '/' );
		$args = array();
		if ( ! empty( $redirect ) ) {
			$args['redirect_to'] = urlencode( $redirect );
		}
		if ( $force_reauth ) {
			$args['reauth'] = '1';
		}
		return empty( $args ) ? $url : add_query_arg( $args, $url );
	}

	/**
	 * logout_url filter.
	 *
	 * @param string $logout_url URL.
	 * @param string $redirect   Redirect.
	 * @return string
	 */
	public function logout_url( $logout_url, $redirect = '' ) {
		return str_replace( 'wp-login.php', $this->slug, $logout_url );
	}
}
