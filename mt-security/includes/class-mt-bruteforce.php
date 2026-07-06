<?php
/**
 * Giới hạn đăng nhập: đếm số lần sai theo IP, khóa IP khi vượt ngưỡng.
 * Dùng transient (tận dụng object cache nếu có) -> nhanh, không truy vấn nặng.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Bruteforce {

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
		// Chặn rất sớm trong quá trình xác thực nếu IP đang bị khóa.
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 1 );
		// Đếm khi đăng nhập thất bại.
		add_action( 'wp_login_failed', array( $this, 'on_failed' ), 10, 1 );
		// Reset bộ đếm khi đăng nhập thành công.
		add_action( 'wp_login', array( $this, 'on_success' ), 10, 2 );
	}

	/**
	 * Khóa transient của IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function attempts_key( $ip ) {
		return 'mt_sec_bf_' . md5( $ip );
	}

	/**
	 * Khóa lockout của IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function lock_key( $ip ) {
		return 'mt_sec_lock_' . md5( $ip );
	}

	/**
	 * Khóa đếm số lần bị khóa (để tăng thời gian khóa khi tái phạm).
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function strikes_key( $ip ) {
		return 'mt_sec_strikes_' . md5( $ip );
	}

	/**
	 * Chặn xác thực nếu IP đang bị khóa.
	 *
	 * @param mixed $user User hoặc WP_Error.
	 * @return mixed
	 */
	public function check_lockout( $user ) {
		// Không can thiệp khi không phải request đăng nhập (vd: cookie auth).
		if ( empty( $_POST['log'] ) && empty( $_POST['pwd'] ) ) {
			return $user;
		}

		// Mật khẩu ĐÚNG (đã được xác thực ở priority trước) -> cho chính chủ đăng
		// nhập kể cả khi IP đang bị khóa. Cơ chế khóa chỉ nhằm chặn việc DÒ mật
		// khẩu SAI, không nên chặn người đã nhập đúng (2FA vẫn áp dụng nếu bật).
		if ( $user instanceof WP_User ) {
			return $user;
		}

		$ip = MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) );

		// IP tin cậy (whitelist) -> không bao giờ bị khóa.
		if ( $this->is_whitelisted( $ip ) ) {
			return $user;
		}

		$until = get_transient( $this->lock_key( $ip ) );

		if ( $until && $until > time() ) {
			$minutes = ceil( ( $until - time() ) / 60 );
			return new WP_Error(
				'mt_sec_locked',
				sprintf(
					/* translators: %d: số phút còn lại */
					__( '<strong>Bị khóa:</strong> Bạn đã đăng nhập sai quá nhiều lần. Vui lòng thử lại sau %d phút.', 'mt-security' ),
					(int) $minutes
				)
			);
		}

		return $user;
	}

	/**
	 * Xử lý khi đăng nhập sai.
	 *
	 * @param string $username Tên đăng nhập đã thử.
	 */
	public function on_failed( $username ) {
		$ip = MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) );

		// IP tin cậy -> không đếm, không khóa.
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}

		$max         = max( 1, (int) $this->s['bf_max_attempts'] );
		$lock_min    = max( 1, (int) $this->s['bf_lockout_minutes'] );
		$window      = $lock_min * 60; // Cửa sổ đếm = thời gian khóa.

		$attempts = (int) get_transient( $this->attempts_key( $ip ) );
		$attempts++;
		set_transient( $this->attempts_key( $ip ), $attempts, $window );

		if ( $attempts >= $max ) {
			// Tăng số lần bị khóa (strike) -> tái phạm thì khóa lâu hơn.
			$strikes = (int) get_transient( $this->strikes_key( $ip ) );
			$strikes++;
			set_transient( $this->strikes_key( $ip ), $strikes, DAY_IN_SECONDS );

			$threshold = max( 1, (int) $this->s['bf_long_threshold'] );
			if ( $strikes >= $threshold && ! empty( $this->s['bf_long_lockout'] ) ) {
				$duration = (int) $this->s['bf_long_lockout'] * HOUR_IN_SECONDS; // Khóa dài.
			} else {
				$duration = $lock_min * 60;
			}

			set_transient( $this->lock_key( $ip ), time() + $duration, $duration );
			delete_transient( $this->attempts_key( $ip ) );

			// Đếm tổng số lần khóa (thống kê hiển thị).
			$total = (int) get_option( 'mt_sec_bf_locks', 0 );
			update_option( 'mt_sec_bf_locks', $total + 1, false );
		}
	}

	/**
	 * Reset khi đăng nhập thành công.
	 *
	 * @param string  $user_login Tên đăng nhập.
	 * @param WP_User $user       Đối tượng user.
	 */
	public function on_success( $user_login, $user ) {
		$ip = MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) );
		delete_transient( $this->attempts_key( $ip ) );
		delete_transient( $this->lock_key( $ip ) );
		delete_transient( $this->strikes_key( $ip ) );
	}

	/**
	 * IP có trong danh sách tin cậy không (dùng chung với tường lửa).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		if ( empty( $this->s['fw_whitelist_ips'] ) ) {
			return false;
		}
		foreach ( preg_split( '/[\r\n,]+/', $this->s['fw_whitelist_ips'] ) as $entry ) {
			$entry = trim( $entry );
			if ( '' !== $entry && $entry === $ip ) {
				return true;
			}
		}
		return false;
	}
}
