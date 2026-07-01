<?php
/**
 * Bảo vệ tài khoản: chặn đăng ký mới & giám sát/phát hiện tài khoản quản trị ẩn.
 *
 * Kiểu tấn công phổ biến: sau khi chiếm quyền, hacker tạo một tài khoản admin
 * rồi dùng filter pre_user_query để ẩn nó khỏi danh sách Users. Module này dò
 * admin bằng truy vấn THẲNG vào bảng usermeta -> lộ nguyên tài khoản ẩn.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_User_Guard {

	/**
	 * Cấu hình.
	 *
	 * @var array
	 */
	private $s;

	/**
	 * Tên option lưu danh sách admin đã được duyệt (baseline).
	 *
	 * @var string
	 */
	private $authorized_option = 'mt_sec_authorized_admins';

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
		// Khởi tạo baseline admin nếu chưa có (lần đầu = coi các admin hiện tại là hợp lệ).
		if ( false === get_option( $this->authorized_option, false ) ) {
			update_option( $this->authorized_option, $this->real_admin_ids(), false );
		}

		// ----- Chặn tạo tài khoản mới (đăng ký công khai) -----
		if ( ! empty( $this->s['block_registration'] ) ) {
			add_filter( 'pre_option_users_can_register', array( $this, 'force_no_register' ), 9999 );
			// Chặn thẳng action=register trên trang đăng nhập.
			add_action( 'login_init', array( $this, 'block_register_action' ), 1 );
			// Chặn tạo user qua REST cho người chưa đăng nhập.
			add_filter( 'rest_pre_insert_user', array( $this, 'block_rest_user' ), 10, 1 );
		}

		// ----- Giám sát tài khoản quản trị -----
		if ( ! empty( $this->s['guard_admins'] ) ) {
			add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
			add_action( 'set_user_role', array( $this, 'on_set_role' ), 10, 3 );

			// Xử lý thao tác trong admin (duyệt / gỡ quyền / xóa).
			if ( is_admin() ) {
				add_action( 'admin_init', array( $this, 'handle_actions' ) );
				add_action( 'admin_notices', array( $this, 'rogue_admin_notice' ) );
			}
		}
	}

	/**
	 * Ép tắt đăng ký.
	 *
	 * @return int
	 */
	public function force_no_register() {
		return 0;
	}

	/**
	 * Chặn action=register.
	 */
	public function block_register_action() {
		$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : '';
		if ( 'register' === $action ) {
			$count = (int) get_option( 'mt_sec_blocked_regs', 0 );
			update_option( 'mt_sec_blocked_regs', $count + 1, false );
			wp_safe_redirect( wp_login_url() );
			exit;
		}
	}

	/**
	 * Chặn tạo user qua REST khi chưa đăng nhập / không đủ quyền.
	 *
	 * @param object $prepared_user Dữ liệu user.
	 * @return object|WP_Error
	 */
	public function block_rest_user( $prepared_user ) {
		if ( ! is_user_logged_in() || ! current_user_can( 'create_users' ) ) {
			return new WP_Error(
				'mt_sec_registration_disabled',
				__( 'Việc tạo tài khoản đã bị vô hiệu hóa.', 'mt-security' ),
				array( 'status' => 403 )
			);
		}
		return $prepared_user;
	}

	/**
	 * Khi có user mới được tạo.
	 *
	 * @param int $user_id User ID.
	 */
	public function on_user_register( $user_id ) {
		$this->guard_user( $user_id, 'created' );
	}

	/**
	 * Khi vai trò user thay đổi.
	 *
	 * @param int      $user_id   User ID.
	 * @param string   $role      Vai trò mới.
	 * @param string[] $old_roles Vai trò cũ.
	 */
	public function on_set_role( $user_id, $role, $old_roles ) {
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
			$this->guard_user( $user_id, 'elevated' );
		}
	}

	/**
	 * Kiểm tra một user: nếu là admin lạ -> cảnh báo (và chặn nếu bật).
	 *
	 * @param int    $user_id User ID.
	 * @param string $context Ngữ cảnh.
	 */
	private function guard_user( $user_id, $context ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		$authorized = (array) get_option( $this->authorized_option, array() );
		if ( in_array( (int) $user_id, array_map( 'intval', $authorized ), true ) ) {
			return; // Admin đã được duyệt.
		}

		// Admin lạ -> gửi cảnh báo.
		$this->alert_rogue_admin( $user, $context );

		// Nếu bật chặn cứng -> hạ quyền ngay, chờ chủ site duyệt thủ công.
		if ( ! empty( $this->s['block_new_admins'] ) ) {
			$obj = new WP_User( $user_id );
			$obj->set_role( 'subscriber' );
			$count = (int) get_option( 'mt_sec_blocked_admins', 0 );
			update_option( 'mt_sec_blocked_admins', $count + 1, false );
		}
	}

	/**
	 * Gửi email cảnh báo có admin lạ.
	 *
	 * @param WP_User $user    User.
	 * @param string  $context Ngữ cảnh.
	 */
	private function alert_rogue_admin( $user, $context ) {
		$to      = ! empty( $this->s['guard_alert_email'] ) ? $this->s['guard_alert_email'] : get_option( 'admin_email' );
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$actor   = is_user_logged_in() ? wp_get_current_user()->user_login : __( '(không rõ / không đăng nhập)', 'mt-security' );
		$blocked = ! empty( $this->s['block_new_admins'] );

		$subject = sprintf( __( '[%s] CẢNH BÁO: Tài khoản quản trị mới', 'mt-security' ), $site );
		$lines   = array(
			__( 'Phát hiện một tài khoản QUẢN TRỊ (administrator) mới trên website của bạn.', 'mt-security' ),
			'',
			sprintf( __( 'Tài khoản: %s', 'mt-security' ), $user->user_login ),
			sprintf( __( 'Email:     %s', 'mt-security' ), $user->user_email ),
			sprintf( __( 'Người tạo: %s', 'mt-security' ), $actor ),
			sprintf( __( 'IP:        %s', 'mt-security' ), MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) ) ),
			'',
			$blocked
				? __( '>> Tài khoản này ĐÃ BỊ HẠ QUYỀN tự động. Vào MT Security để duyệt nếu là của bạn.', 'mt-security' )
				: __( '>> Nếu KHÔNG phải bạn tạo, hãy vào MT Security để gỡ quyền/xóa ngay.', 'mt-security' ),
			admin_url( 'admin.php?page=mt-security' ),
		);
		wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Lấy danh sách ID admin THỰC (truy vấn thẳng usermeta -> bỏ qua mọi filter che giấu).
	 *
	 * @return int[]
	 */
	public function real_admin_ids() {
		global $wpdb;
		$meta_key = $wpdb->prefix . 'capabilities';
		$ids      = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s",
				$meta_key,
				'%administrator%'
			)
		);
		return array_map( 'intval', (array) $ids );
	}

	/**
	 * Báo cáo admin: đánh dấu admin lạ (chưa duyệt) và admin bị ẩn.
	 *
	 * @return array
	 */
	public function get_admin_report() {
		$real_ids   = $this->real_admin_ids();
		$authorized = array_map( 'intval', (array) get_option( $this->authorized_option, array() ) );

		// ID admin mà WP_User_Query "nhìn thấy" (có thể bị filter che bớt).
		$visible = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
		$visible = array_map( 'intval', (array) $visible );

		$report = array();
		foreach ( $real_ids as $id ) {
			$u = get_userdata( $id );
			if ( ! $u ) {
				continue;
			}
			$report[] = array(
				'id'         => $id,
				'login'      => $u->user_login,
				'email'      => $u->user_email,
				'registered' => $u->user_registered,
				'authorized' => in_array( $id, $authorized, true ),
				'hidden'     => ! in_array( $id, $visible, true ), // Có trong DB nhưng bị ẩn khỏi danh sách.
			);
		}
		return $report;
	}

	/**
	 * Xử lý thao tác duyệt / gỡ quyền / xóa từ trang cài đặt.
	 */
	public function handle_actions() {
		if ( empty( $_GET['mt_sec_ug'] ) || empty( $_GET['uid'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$action = sanitize_key( $_GET['mt_sec_ug'] );
		$uid    = (int) $_GET['uid'];

		check_admin_referer( 'mt_sec_ug_' . $uid );

		$authorized = array_map( 'intval', (array) get_option( $this->authorized_option, array() ) );

		if ( 'authorize' === $action ) {
			if ( ! in_array( $uid, $authorized, true ) ) {
				$authorized[] = $uid;
				update_option( $this->authorized_option, $authorized, false );
			}
			// Nếu đã bị hạ quyền trước đó thì khôi phục lại admin.
			$u = get_userdata( $uid );
			if ( $u && ! in_array( 'administrator', (array) $u->roles, true ) ) {
				( new WP_User( $uid ) )->set_role( 'administrator' );
			}
		} elseif ( 'revoke' === $action ) {
			// Không tự gỡ quyền chính mình để tránh mất quyền.
			if ( $uid !== get_current_user_id() ) {
				( new WP_User( $uid ) )->set_role( 'subscriber' );
				$authorized = array_values( array_diff( $authorized, array( $uid ) ) );
				update_option( $this->authorized_option, $authorized, false );
			}
		} elseif ( 'delete' === $action ) {
			if ( $uid !== get_current_user_id() ) {
				require_once ABSPATH . 'wp-admin/includes/user.php';
				wp_delete_user( $uid );
				$authorized = array_values( array_diff( $authorized, array( $uid ) ) );
				update_option( $this->authorized_option, $authorized, false );
			}
		}

		wp_safe_redirect( admin_url( 'admin.php?page=mt-security&mt_sec_done=1#user-guard' ) );
		exit;
	}

	/**
	 * Hiện cảnh báo trên đầu admin nếu có admin lạ / admin ẩn.
	 */
	public function rogue_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$report = $this->get_admin_report();
		$rogue  = 0;
		$hidden = 0;
		foreach ( $report as $r ) {
			if ( ! $r['authorized'] ) {
				$rogue++;
			}
			if ( $r['hidden'] ) {
				$hidden++;
			}
		}
		if ( $rogue || $hidden ) {
			echo '<div class="notice notice-error"><p>';
			echo '<strong>MT Security:</strong> ';
			if ( $hidden ) {
				printf( esc_html__( 'Phát hiện %d tài khoản admin ĐANG BỊ ẨN! ', 'mt-security' ), (int) $hidden );
			}
			if ( $rogue ) {
				printf( esc_html__( 'Có %d tài khoản admin chưa được duyệt. ', 'mt-security' ), (int) $rogue );
			}
			echo '<a href="' . esc_url( admin_url( 'admin.php?page=mt-security#user-guard' ) ) . '">' . esc_html__( 'Kiểm tra ngay', 'mt-security' ) . '</a>';
			echo '</p></div>';
		}
	}

	/**
	 * URL thao tác có nonce.
	 *
	 * @param string $action Hành động.
	 * @param int    $uid    User ID.
	 * @return string
	 */
	public static function action_url( $action, $uid ) {
		$url = admin_url( 'admin.php?page=mt-security&mt_sec_ug=' . $action . '&uid=' . $uid );
		return wp_nonce_url( $url, 'mt_sec_ug_' . $uid );
	}
}
