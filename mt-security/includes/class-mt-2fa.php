<?php
/**
 * Đăng nhập 2 lớp (2FA).
 *
 * Hỗ trợ 2 phương thức:
 *   - totp : mã 6 số đổi liên tục từ app (Google Authenticator, Authy, Microsoft Authenticator...).
 *   - email: mã OTP gửi qua email.
 * Kèm MÃ DỰ PHÒNG (backup codes) dùng một lần khi mất thiết bị / không nhận được email.
 *
 * TOTP theo chuẩn RFC 6238, tự triển khai, không phụ thuộc thư viện ngoài.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Two_Factor {

	/**
	 * Cấu hình.
	 *
	 * @var array
	 */
	private $s;

	const META_SECRET  = 'mt_sec_2fa_secret';
	const META_ACTIVE  = 'mt_sec_2fa_active';
	const META_BACKUP  = 'mt_sec_2fa_backup';

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
		// Luồng đăng nhập (cần cả ở front-end/wp-login).
		add_filter( 'authenticate', array( $this, 'verify_step' ), 5, 1 );
		add_filter( 'authenticate', array( $this, 'request_step' ), 50, 1 );

		// Các hook dưới đây chỉ dùng trong khu vực quản trị -> không đăng ký ở front-end.
		if ( is_admin() ) {
			// Thiết lập 2FA trong trang hồ sơ user.
			add_action( 'show_user_profile', array( $this, 'profile_fields' ) );
			add_action( 'edit_user_profile', array( $this, 'profile_fields' ) );
			add_action( 'personal_options_update', array( $this, 'save_profile' ) );
			add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );

			// Nhắc user bắt buộc 2FA nhưng chưa thiết lập.
			add_action( 'admin_notices', array( $this, 'enroll_notice' ) );
		}
	}

	/* ============================================================
	 *  PHƯƠNG THỨC & TRẠNG THÁI
	 * ============================================================ */

	/**
	 * Phương thức đang chọn.
	 *
	 * @return string 'totp' | 'email'
	 */
	private function method() {
		return ( isset( $this->s['2fa_method'] ) && 'email' === $this->s['2fa_method'] ) ? 'email' : 'totp';
	}

	/**
	 * Vai trò user có cần 2FA không.
	 *
	 * @param WP_User $user User.
	 * @return bool
	 */
	private function needs_2fa( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return false;
		}
		$roles = isset( $this->s['2fa_roles'] ) && is_array( $this->s['2fa_roles'] ) ? $this->s['2fa_roles'] : array();
		foreach ( (array) $user->roles as $r ) {
			if ( in_array( $r, $roles, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * User đã kích hoạt 2FA chưa (với phương thức hiện tại).
	 * Email không cần "kích hoạt" vì dùng email tài khoản.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function is_active( $user_id ) {
		if ( 'email' === $this->method() ) {
			return true;
		}
		return '1' === get_user_meta( $user_id, self::META_ACTIVE, true )
			&& '' !== get_user_meta( $user_id, self::META_SECRET, true );
	}

	private function pending_key( $token ) {
		return 'mt_sec_2fa_' . $token;
	}

	private function code_ttl() {
		return max( 1, (int) $this->s['2fa_code_ttl'] ) * MINUTE_IN_SECONDS;
	}

	/* ============================================================
	 *  LUỒNG ĐĂNG NHẬP
	 * ============================================================ */

	/**
	 * Bước 2: xác minh mã (TOTP / email OTP / mã dự phòng).
	 *
	 * @param mixed $user User/WP_Error/null.
	 * @return mixed
	 */
	public function verify_step( $user ) {
		if ( empty( $_POST['mt_2fa_token'] ) || ! isset( $_POST['mt_2fa_code'] ) ) {
			return $user;
		}

		$token   = sanitize_text_field( wp_unslash( $_POST['mt_2fa_token'] ) );
		$pending = get_transient( $this->pending_key( $token ) );

		if ( empty( $pending ) || empty( $pending['user_id'] ) ) {
			$this->render_form( '', '', __( 'Phiên đã hết hạn. Vui lòng đăng nhập lại.', 'mt-security' ), true );
		}

		if ( (int) $pending['attempts'] >= 5 ) {
			delete_transient( $this->pending_key( $token ) );
			$this->render_form( '', '', __( 'Nhập sai quá nhiều lần. Vui lòng đăng nhập lại.', 'mt-security' ), true );
		}

		$user_id = (int) $pending['user_id'];
		$raw     = (string) wp_unslash( $_POST['mt_2fa_code'] );
		$digits  = preg_replace( '/\D/', '', $raw );
		$ok      = false;

		// 1) Mã chính theo phương thức.
		if ( 'email' === $pending['method'] ) {
			if ( ! empty( $pending['code'] ) && strlen( $digits ) === 6 && hash_equals( (string) $pending['code'], $digits ) ) {
				$ok = true;
			}
		} else {
			$secret = get_user_meta( $user_id, self::META_SECRET, true );
			if ( $secret && strlen( $digits ) === 6 && $this->totp_verify( $secret, $digits ) ) {
				$ok = true;
			}
		}

		// 2) Nếu mã chính sai -> thử mã dự phòng.
		if ( ! $ok && $this->consume_backup_code( $user_id, $raw ) ) {
			$ok = true;
		}

		if ( $ok ) {
			delete_transient( $this->pending_key( $token ) );
			$verified = get_user_by( 'id', $user_id );
			return $verified ? $verified : $user;
		}

		// Sai -> tăng đếm & hiện lại form.
		$pending['attempts']++;
		set_transient( $this->pending_key( $token ), $pending, $this->code_ttl() );
		$this->render_form( $token, isset( $pending['redirect'] ) ? $pending['redirect'] : '', __( 'Mã không đúng. Vui lòng thử lại.', 'mt-security' ) );
	}

	/**
	 * Bước 1: sau khi mật khẩu đúng -> yêu cầu 2FA.
	 *
	 * @param mixed $user User/WP_Error/null.
	 * @return mixed
	 */
	public function request_step( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! empty( $_POST['mt_2fa_token'] ) ) {
			return $user; // Đã ở bước xác minh.
		}
		if ( ! $this->needs_2fa( $user ) ) {
			return $user;
		}

		$method = $this->method();

		// TOTP nhưng user chưa thiết lập -> cho vào, nhắc thiết lập (tránh khóa nhầm).
		if ( 'totp' === $method && ! $this->is_active( $user->ID ) ) {
			return $user;
		}

		$token    = wp_generate_password( 20, false );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$pending  = array(
			'user_id'  => $user->ID,
			'method'   => $method,
			'attempts' => 0,
			'redirect' => $redirect,
		);

		if ( 'email' === $method ) {
			$code            = str_pad( (string) wp_rand( 0, 999999 ), 6, '0', STR_PAD_LEFT );
			$pending['code'] = $code;
			$this->send_email_code( $user, $code );
		}

		set_transient( $this->pending_key( $token ), $pending, $this->code_ttl() );
		$this->render_form( $token, $redirect, '', false, $method );
	}

	/**
	 * Gửi mã OTP qua email.
	 *
	 * @param WP_User $user User.
	 * @param string  $code Mã.
	 */
	private function send_email_code( $user, $code ) {
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$minutes = max( 1, (int) $this->s['2fa_code_ttl'] );
		$subject = sprintf( __( '[%s] Mã đăng nhập của bạn', 'mt-security' ), $site );
		$message = sprintf(
			/* translators: 1: name, 2: code, 3: minutes */
			__( "Xin chào %1\$s,\n\nMã xác thực đăng nhập: %2\$s\n\nHiệu lực trong %3\$d phút. Nếu không phải bạn, hãy đổi mật khẩu ngay.\n", 'mt-security' ),
			$user->display_name,
			$code,
			$minutes
		);
		wp_mail( $user->user_email, $subject, $message );
	}

	/**
	 * Hiển thị form nhập mã rồi dừng.
	 *
	 * @param string $token    Token.
	 * @param string $redirect Redirect.
	 * @param string $error    Lỗi.
	 * @param bool   $expired  Hết hạn.
	 * @param string $method   Phương thức.
	 */
	private function render_form( $token, $redirect = '', $error = '', $expired = false, $method = '' ) {
		if ( ! function_exists( 'login_header' ) ) {
			require_once ABSPATH . 'wp-login.php';
		}
		$action_url = site_url( 'wp-login.php', 'login_post' );

		login_header( __( 'Xác thực 2 lớp', 'mt-security' ), '', null );

		if ( $error ) {
			echo '<div id="login_error">' . wp_kses_post( $error ) . '</div>';
		}

		if ( $expired ) {
			echo '<p>' . esc_html__( 'Phiên xác thực đã kết thúc.', 'mt-security' ) . '</p>';
			echo '<p><a href="' . esc_url( wp_login_url( $redirect ) ) . '">' . esc_html__( 'Quay lại đăng nhập', 'mt-security' ) . '</a></p>';
			login_footer();
			exit;
		}

		$hint = ( 'email' === $method )
			? __( 'Nhập mã 6 số vừa gửi tới email của bạn', 'mt-security' )
			: __( 'Nhập mã 6 số trong app xác thực', 'mt-security' );
		?>
		<form name="mt2fa" id="loginform" action="<?php echo esc_url( $action_url ); ?>" method="post">
			<p>
				<label for="mt_2fa_code"><?php echo esc_html( $hint ); ?></label>
				<input type="text" name="mt_2fa_code" id="mt_2fa_code" class="input"
					inputmode="text" autocomplete="one-time-code"
					maxlength="20" autofocus="autofocus" />
			</p>
			<p class="description" style="margin-bottom:12px;">
				<?php esc_html_e( 'Mất thiết bị? Nhập một mã dự phòng vào ô trên.', 'mt-security' ); ?>
			</p>
			<input type="hidden" name="mt_2fa_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large"
					value="<?php esc_attr_e( 'Xác nhận', 'mt-security' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'mt_2fa_code' );
		exit;
	}

	/* ============================================================
	 *  THIẾT LẬP TRONG HỒ SƠ USER
	 * ============================================================ */

	/**
	 * Hiển thị phần thiết lập 2FA trong hồ sơ.
	 *
	 * @param WP_User $user User.
	 */
	public function profile_fields( $user ) {
		// Email method không cần thiết lập.
		if ( 'totp' !== $this->method() ) {
			return;
		}
		// Chỉ hiện với chính chủ (không cho admin xem secret người khác).
		if ( get_current_user_id() !== $user->ID ) {
			echo '<h2>' . esc_html__( 'Bảo mật 2 lớp (MT Security)', 'mt-security' ) . '</h2>';
			echo '<p class="description">' . esc_html__( 'Chỉ chủ tài khoản mới thiết lập được 2FA của mình.', 'mt-security' ) . '</p>';
			return;
		}

		$active = $this->is_active( $user->ID );
		wp_nonce_field( 'mt_sec_2fa_profile', 'mt_sec_2fa_nonce' );
		echo '<h2>' . esc_html__( 'Bảo mật 2 lớp (MT Security)', 'mt-security' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tbody>';

		if ( $active ) {
			$remaining = count( (array) get_user_meta( $user->ID, self::META_BACKUP, true ) );
			echo '<tr><th>' . esc_html__( 'Trạng thái', 'mt-security' ) . '</th><td>';
			echo '<span style="color:#227a22;font-weight:600;">● ' . esc_html__( 'ĐANG BẬT', 'mt-security' ) . '</span>';
			echo '<p><label><input type="checkbox" name="mt_sec_2fa_disable" value="1"> ' . esc_html__( 'Tắt 2FA cho tài khoản này', 'mt-security' ) . '</label></p>';
			echo '<p>' . sprintf( esc_html__( 'Mã dự phòng còn lại: %d', 'mt-security' ), (int) $remaining ) . '</p>';
			echo '<p><label><input type="checkbox" name="mt_sec_2fa_regen" value="1"> ' . esc_html__( 'Tạo lại bộ mã dự phòng mới', 'mt-security' ) . '</label></p>';
			echo '</td></tr>';
		} else {
			// Sinh secret tạm nếu chưa có để hiển thị.
			$secret = get_user_meta( $user->ID, self::META_SECRET, true );
			if ( ! $secret ) {
				$secret = $this->generate_secret();
				update_user_meta( $user->ID, self::META_SECRET, $secret );
			}
			$otpauth = $this->otpauth_uri( $user, $secret );

			echo '<tr><th>' . esc_html__( 'Thiết lập app xác thực', 'mt-security' ) . '</th><td>';
			echo '<ol style="margin-top:0;">';
			echo '<li>' . esc_html__( 'Cài app: Google Authenticator, Authy hoặc Microsoft Authenticator.', 'mt-security' ) . '</li>';
			echo '<li>' . esc_html__( 'Thêm tài khoản mới bằng cách nhập KHÓA thủ công dưới đây (hoặc mở link trên điện thoại):', 'mt-security' ) . '</li>';
			echo '</ol>';
			echo '<p><strong>' . esc_html__( 'Khóa:', 'mt-security' ) . '</strong> <code style="font-size:15px;letter-spacing:2px;">' . esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ) . '</code></p>';
			echo '<p><a href="' . esc_url( $otpauth ) . '">' . esc_html__( 'Mở trong app xác thực (trên điện thoại)', 'mt-security' ) . '</a></p>';
			echo '<p style="margin-top:14px;"><label>' . esc_html__( 'Nhập mã 6 số từ app để kích hoạt:', 'mt-security' ) . '<br>';
			echo '<input type="text" name="mt_sec_2fa_confirm" inputmode="numeric" maxlength="6" class="regular-text" autocomplete="off" style="letter-spacing:4px;"></label></p>';
			echo '<p class="description">' . esc_html__( 'Sau khi bấm "Cập nhật hồ sơ", bộ mã dự phòng sẽ hiện ra — hãy lưu lại.', 'mt-security' ) . '</p>';
			echo '</td></tr>';
		}

		// Hiện mã dự phòng vừa tạo (một lần).
		$show = get_transient( 'mt_sec_2fa_show_' . $user->ID );
		if ( ! empty( $show ) && is_array( $show ) ) {
			delete_transient( 'mt_sec_2fa_show_' . $user->ID );
			echo '<tr><th>' . esc_html__( 'MÃ DỰ PHÒNG (lưu lại ngay!)', 'mt-security' ) . '</th><td>';
			echo '<div style="background:#fff8e5;border:1px solid #f0c33c;padding:12px 16px;border-radius:6px;font-family:monospace;font-size:15px;line-height:2;">';
			foreach ( $show as $c ) {
				echo esc_html( $c ) . '<br>';
			}
			echo '</div>';
			echo '<p class="description">' . esc_html__( 'Mỗi mã dùng được một lần. Cất nơi an toàn — sẽ không hiển thị lại.', 'mt-security' ) . '</p>';
			echo '</td></tr>';
		}

		echo '</tbody></table>';
	}

	/**
	 * Lưu thiết lập 2FA từ hồ sơ.
	 *
	 * @param int $user_id User ID.
	 */
	public function save_profile( $user_id ) {
		if ( 'totp' !== $this->method() ) {
			return;
		}
		if ( get_current_user_id() !== (int) $user_id ) {
			return; // Chỉ chính chủ.
		}
		if ( empty( $_POST['mt_sec_2fa_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['mt_sec_2fa_nonce'] ) ), 'mt_sec_2fa_profile' ) ) {
			return;
		}

		// Tắt 2FA.
		if ( ! empty( $_POST['mt_sec_2fa_disable'] ) ) {
			delete_user_meta( $user_id, self::META_ACTIVE );
			delete_user_meta( $user_id, self::META_SECRET );
			delete_user_meta( $user_id, self::META_BACKUP );
			return;
		}

		$active = ( '1' === get_user_meta( $user_id, self::META_ACTIVE, true ) );

		// Kích hoạt lần đầu.
		if ( ! $active && isset( $_POST['mt_sec_2fa_confirm'] ) ) {
			$code   = preg_replace( '/\D/', '', (string) wp_unslash( $_POST['mt_sec_2fa_confirm'] ) );
			$secret = get_user_meta( $user_id, self::META_SECRET, true );
			if ( $secret && strlen( $code ) === 6 && $this->totp_verify( $secret, $code ) ) {
				update_user_meta( $user_id, self::META_ACTIVE, '1' );
				$this->issue_backup_codes( $user_id );
			}
			return;
		}

		// Tạo lại mã dự phòng.
		if ( $active && ! empty( $_POST['mt_sec_2fa_regen'] ) ) {
			$this->issue_backup_codes( $user_id );
		}
	}

	/**
	 * Nhắc user bắt buộc 2FA nhưng chưa bật.
	 */
	public function enroll_notice() {
		if ( 'totp' !== $this->method() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user || ! $this->needs_2fa( $user ) || $this->is_active( $user->ID ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo '<strong>MT Security:</strong> ' . esc_html__( 'Tài khoản của bạn cần bật xác thực 2 lớp. ', 'mt-security' );
		echo '<a href="' . esc_url( get_edit_profile_url( $user->ID ) ) . '#mt_sec_2fa_confirm">' . esc_html__( 'Thiết lập ngay', 'mt-security' ) . '</a>';
		echo '</p></div>';
	}

	/* ============================================================
	 *  MÃ DỰ PHÒNG
	 * ============================================================ */

	/**
	 * Cấp bộ mã dự phòng mới, lưu bản băm, trả bản gốc qua transient để hiển thị.
	 *
	 * @param int $user_id User ID.
	 */
	private function issue_backup_codes( $user_id ) {
		$count  = max( 1, (int) $this->s['2fa_backup_count'] );
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$raw   = bin2hex( random_bytes( 5 ) ); // 10 ký tự hex.
			$code  = substr( $raw, 0, 5 ) . '-' . substr( $raw, 5, 5 );
			$plain[]  = $code;
			$hashes[] = hash( 'sha256', $this->normalize_code( $code ) );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashes );
		set_transient( 'mt_sec_2fa_show_' . $user_id, $plain, 10 * MINUTE_IN_SECONDS );
	}

	/**
	 * Chuẩn hóa mã (bỏ ký tự phân cách, chữ thường).
	 *
	 * @param string $code Mã.
	 * @return string
	 */
	private function normalize_code( $code ) {
		return strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $code ) );
	}

	/**
	 * Kiểm tra & tiêu thụ một mã dự phòng.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Mã người dùng nhập.
	 * @return bool
	 */
	private function consume_backup_code( $user_id, $code ) {
		$norm = $this->normalize_code( $code );
		if ( strlen( $norm ) < 6 ) {
			return false;
		}
		$hashes = (array) get_user_meta( $user_id, self::META_BACKUP, true );
		if ( empty( $hashes ) ) {
			return false;
		}
		$target = hash( 'sha256', $norm );
		foreach ( $hashes as $i => $h ) {
			if ( hash_equals( (string) $h, $target ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );
				return true;
			}
		}
		return false;
	}

	/* ============================================================
	 *  TOTP (RFC 6238) + BASE32
	 * ============================================================ */

	/**
	 * Sinh secret Base32 (160-bit).
	 *
	 * @return string
	 */
	private function generate_secret() {
		return $this->base32_encode( random_bytes( 20 ) );
	}

	/**
	 * URI otpauth để nạp vào app.
	 *
	 * @param WP_User $user   User.
	 * @param string  $secret Secret.
	 * @return string
	 */
	private function otpauth_uri( $user, $secret ) {
		$issuer  = rawurlencode( wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$account = rawurlencode( $user->user_login );
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			$issuer,
			$account,
			$secret,
			$issuer
		);
	}

	/**
	 * Sinh mã TOTP cho một counter.
	 *
	 * @param string $secret  Secret Base32.
	 * @param int    $counter Bộ đếm thời gian.
	 * @return string
	 */
	private function totp_code( $secret, $counter ) {
		$key = $this->base32_decode( $secret );

		// 8 byte big-endian của counter (không dùng pack('J') để tương thích rộng).
		$data = '';
		for ( $i = 7; $i >= 0; $i-- ) {
			$data .= chr( ( $counter >> ( $i * 8 ) ) & 0xff );
		}

		$hash   = hash_hmac( 'sha1', $data, $key, true );
		$offset = ord( $hash[19] ) & 0x0f;
		$part   = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );

		return str_pad( (string) ( $part % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Xác minh mã TOTP với cửa sổ ±1 bước (±30 giây).
	 *
	 * @param string $secret Secret.
	 * @param string $code   Mã người dùng nhập.
	 * @return bool
	 */
	private function totp_verify( $secret, $code ) {
		$counter = (int) floor( time() / 30 );
		for ( $o = -1; $o <= 1; $o++ ) {
			if ( hash_equals( $this->totp_code( $secret, $counter + $o ), (string) $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Base32 encode (RFC 4648, không padding).
	 *
	 * @param string $data Dữ liệu nhị phân.
	 * @return string
	 */
	private function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		$len      = strlen( $data );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		$n   = strlen( $bits );
		for ( $i = 0; $i + 5 <= $n; $i += 5 ) {
			$out .= $alphabet[ bindec( substr( $bits, $i, 5 ) ) ];
		}
		$rem = $n % 5;
		if ( $rem ) {
			$out .= $alphabet[ bindec( str_pad( substr( $bits, -$rem ), 5, '0' ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $b32 Chuỗi Base32.
	 * @return string
	 */
	private function base32_decode( $b32 ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32      = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $b32 ) );
		$bits     = '';
		$len      = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$val = strpos( $alphabet, $b32[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$bits .= str_pad( decbin( $val ), 5, '0', STR_PAD_LEFT );
		}
		$bytes = '';
		$n     = strlen( $bits );
		for ( $i = 0; $i + 8 <= $n; $i += 8 ) {
			$bytes .= chr( bindec( substr( $bits, $i, 8 ) ) );
		}
		return $bytes;
	}
}
