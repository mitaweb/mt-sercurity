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
		add_action( 'plugins_loaded', array( $this, 'intercept' ), 1 );
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
			$allowed_actions = array( 'logout', 'postpass', 'rp', 'resetpass' );
			if ( in_array( $action, $allowed_actions, true ) ) {
				return;
			}
			$this->deny();
		}

		// 3) Khách (chưa đăng nhập) gõ /wp-admin -> 404 (trừ admin-ajax & admin-post).
		if ( ! is_user_logged_in() && 0 === strpos( $path, 'wp-admin' ) ) {
			if ( false !== strpos( $_SERVER['REQUEST_URI'], 'admin-ajax.php' ) ||
				false !== strpos( $_SERVER['REQUEST_URI'], 'admin-post.php' ) ) {
				return;
			}
			$this->deny();
		}
	}

	/**
	 * Trả về 404 không lộ thông tin.
	 */
	private function deny() {
		status_header( 404 );
		nocache_headers();
		// Cố gắng dùng template 404 của theme cho tự nhiên.
		if ( function_exists( 'get_query_template' ) ) {
			$tpl = get_query_template( '404' );
			if ( $tpl ) {
				global $wp_query;
				if ( $wp_query ) {
					$wp_query->set_404();
				}
				include $tpl;
				exit;
			}
		}
		exit( '404 Not Found' );
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
