<?php
/**
 * Gia cố WordPress: ẩn phiên bản, tắt XML-RPC, chặn dò user, gỡ thông tin lộ.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Hardening {

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
	 * Chạy module.
	 */
	public function run() {
		// ----- Ẩn phiên bản WordPress -----
		if ( ! empty( $this->s['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			// Gỡ ?ver=x.x.x khỏi CSS/JS (chỉ với asset của core, để không phá cache-busting của theme).
			add_filter( 'style_loader_src', array( $this, 'strip_core_version' ), 9999, 1 );
			add_filter( 'script_loader_src', array( $this, 'strip_core_version' ), 9999, 1 );
			// Gỡ generator khỏi RSS.
			add_filter( 'get_the_generator_html', '__return_empty_string' );
			add_filter( 'get_the_generator_xhtml', '__return_empty_string' );
		}

		// ----- Tắt XML-RPC (gồm các filter anh tham khảo) -----
		if ( ! empty( $this->s['disable_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'pings_open', '__return_false', 9999 );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
			// Chặn thẳng file xmlrpc.php nếu bị gọi trực tiếp.
			add_action( 'init', array( $this, 'block_xmlrpc_request' ), 1 );
			// Gỡ phương thức pingback khỏi danh sách XML-RPC (nếu vẫn còn bật ở nơi khác).
			add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_methods' ) );
			// Gỡ link RSD/WLW manifest trong head.
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}

		// ----- Cấm sửa file trong admin -----
		if ( ! empty( $this->s['disable_file_edit'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// ----- Chặn dò username (?author=1, /?author=...) -----
		if ( ! empty( $this->s['block_user_enum'] ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_scan' ) );
			// Bỏ chỉ mục ID tác giả ở comment.
			add_filter( 'redirect_canonical', array( $this, 'block_author_canonical' ), 10, 2 );
		}

		// ----- Ẩn user qua REST API -----
		if ( ! empty( $this->s['disable_rest_users'] ) ) {
			add_filter( 'rest_endpoints', array( $this, 'disable_rest_user_endpoints' ) );
		}

		// ----- Chặn truy cập readme.html / license.txt (lộ version) -----
		if ( ! empty( $this->s['remove_readme'] ) ) {
			add_action( 'init', array( $this, 'block_readme_files' ), 1 );
		}
	}

	/**
	 * Gỡ query ?ver khỏi asset của WordPress core.
	 *
	 * @param string $src URL asset.
	 * @return string
	 */
	public function strip_core_version( $src ) {
		if ( $src && false !== strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Gỡ header X-Pingback.
	 *
	 * @param array $headers Headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'], $headers['x-pingback'] );
		return $headers;
	}

	/**
	 * Gỡ các phương thức pingback của XML-RPC.
	 *
	 * @param array $methods Phương thức.
	 * @return array
	 */
	public function remove_pingback_methods( $methods ) {
		unset(
			$methods['pingback.ping'],
			$methods['pingback.extensions.getPingbacks'],
			$methods['system.multicall']
		);
		return $methods;
	}

	/**
	 * Chặn request trực tiếp tới xmlrpc.php.
	 */
	public function block_xmlrpc_request() {
		if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && 'xmlrpc.php' === basename( $_SERVER['SCRIPT_FILENAME'] ) ) {
			status_header( 403 );
			exit( '403 Forbidden' );
		}
	}

	/**
	 * Chặn dò user qua ?author=N.
	 */
	public function block_author_scan() {
		if ( is_admin() ) {
			return;
		}
		if ( isset( $_GET['author'] ) && ! empty( $_GET['author'] ) ) {
			// Nếu là số -> đây là kiểu dò username.
			if ( preg_match( '/^\d+$/', trim( $_GET['author'] ) ) ) {
				wp_safe_redirect( home_url(), 301 );
				exit;
			}
		}
	}

	/**
	 * Chặn redirect canonical lộ tác giả.
	 *
	 * @param string $redirect_url  URL đích.
	 * @param string $requested_url URL yêu cầu.
	 * @return string|false
	 */
	public function block_author_canonical( $redirect_url, $requested_url ) {
		if ( preg_match( '/\?author=\d+/i', $requested_url ) ) {
			return false;
		}
		return $redirect_url;
	}

	/**
	 * Tắt endpoint liệt kê user của REST API cho khách.
	 *
	 * @param array $endpoints Danh sách endpoint.
	 * @return array
	 */
	public function disable_rest_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints; // Người đã đăng nhập vẫn dùng bình thường (admin, Gutenberg...).
		}
		if ( isset( $endpoints['/wp/v2/users'] ) ) {
			unset( $endpoints['/wp/v2/users'] );
		}
		if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}

	/**
	 * Chặn truy cập readme.html và license.txt.
	 */
	public function block_readme_files() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( $_SERVER['REQUEST_URI'] ) : '';
		if ( false !== strpos( $uri, '/readme.html' ) || false !== strpos( $uri, '/license.txt' ) ) {
			status_header( 403 );
			exit( '403 Forbidden' );
		}
	}
}
