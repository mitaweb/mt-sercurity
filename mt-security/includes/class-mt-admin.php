<?php
/**
 * Trang quản trị & cài đặt cho MT Security.
 * Chỉ nạp trong admin -> không ảnh hưởng tốc độ front-end.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Admin {

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
	 * Chạy.
	 */
	public function run() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_filter( 'plugin_action_links_' . MT_SEC_BASENAME, array( $this, 'action_links' ) );
		add_action( 'update_option_' . MT_SEC_OPTION, array( $this, 'on_save' ), 10, 2 );
	}

	/**
	 * Thêm menu.
	 */
	public function add_menu() {
		add_menu_page(
			__( 'MT Security', 'mt-security' ),
			__( 'MT Security', 'mt-security' ),
			'manage_options',
			'mt-security',
			array( $this, 'render_page' ),
			'dashicons-shield-alt',
			80
		);
	}

	/**
	 * Link nhanh tới cài đặt ở trang Plugins.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function action_links( $links ) {
		$url  = admin_url( 'admin.php?page=mt-security' );
		$link = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Cài đặt', 'mt-security' ) . '</a>';
		array_unshift( $links, $link );
		return $links;
	}

	/**
	 * Đăng ký setting + sanitize.
	 */
	public function register_settings() {
		register_setting(
			'mt_security_group',
			MT_SEC_OPTION,
			array( $this, 'sanitize' )
		);
	}

	/**
	 * Khi lưu cài đặt: flush rewrite nếu liên quan login url.
	 *
	 * @param array $old Cũ.
	 * @param array $new Mới.
	 */
	public function on_save( $old, $new ) {
		$old_login = isset( $old['custom_login'] ) ? $old['custom_login'] : 0;
		$old_slug  = isset( $old['login_slug'] ) ? $old['login_slug'] : '';
		$new_login = isset( $new['custom_login'] ) ? $new['custom_login'] : 0;
		$new_slug  = isset( $new['login_slug'] ) ? $new['login_slug'] : '';
		if ( $old_login !== $new_login || $old_slug !== $new_slug ) {
			flush_rewrite_rules();
		}
	}

	/**
	 * Làm sạch dữ liệu trước khi lưu.
	 *
	 * @param array $input Dữ liệu gửi lên.
	 * @return array
	 */
	public function sanitize( $input ) {
		$d   = MT_Security::default_settings();
		$out = array();

		// Các khóa bật/tắt (checkbox).
		$bools = array(
			'firewall', 'hardening', 'antispam', 'brute_force', 'custom_login', 'two_factor', 'user_guard',
			'hide_wp_version', 'disable_xmlrpc', 'disable_file_edit', 'block_user_enum',
			'disable_rest_users', 'remove_readme',
			'spam_honeypot', 'spam_block_keywords',
			'fw_block_bad_agents', 'fw_block_sqli', 'fw_block_xss', 'fw_protect_files', 'fw_trust_proxy',
			'block_registration', 'guard_admins', 'block_new_admins',
		);
		foreach ( $bools as $k ) {
			$out[ $k ] = empty( $input[ $k ] ) ? 0 : 1;
		}

		// Số.
		$out['spam_min_time']    = isset( $input['spam_min_time'] ) ? max( 0, (int) $input['spam_min_time'] ) : $d['spam_min_time'];
		$out['spam_max_links']   = isset( $input['spam_max_links'] ) ? max( 0, (int) $input['spam_max_links'] ) : $d['spam_max_links'];
		$out['bf_max_attempts']  = isset( $input['bf_max_attempts'] ) ? max( 1, (int) $input['bf_max_attempts'] ) : $d['bf_max_attempts'];
		$out['bf_lockout_minutes'] = isset( $input['bf_lockout_minutes'] ) ? max( 1, (int) $input['bf_lockout_minutes'] ) : $d['bf_lockout_minutes'];
		$out['bf_long_lockout']  = isset( $input['bf_long_lockout'] ) ? max( 0, (int) $input['bf_long_lockout'] ) : $d['bf_long_lockout'];
		$out['bf_long_threshold'] = isset( $input['bf_long_threshold'] ) ? max( 1, (int) $input['bf_long_threshold'] ) : $d['bf_long_threshold'];
		$out['2fa_code_ttl']     = isset( $input['2fa_code_ttl'] ) ? max( 1, (int) $input['2fa_code_ttl'] ) : $d['2fa_code_ttl'];
		$out['2fa_backup_count'] = isset( $input['2fa_backup_count'] ) ? max( 1, (int) $input['2fa_backup_count'] ) : $d['2fa_backup_count'];

		// Phương thức 2FA.
		$out['2fa_method'] = ( isset( $input['2fa_method'] ) && 'email' === $input['2fa_method'] ) ? 'email' : 'totp';

		// Email nhận cảnh báo User Guard.
		$email = isset( $input['guard_alert_email'] ) ? sanitize_email( $input['guard_alert_email'] ) : '';
		$out['guard_alert_email'] = ( $email && is_email( $email ) ) ? $email : '';

		// Slug login.
		$slug = isset( $input['login_slug'] ) ? sanitize_title( $input['login_slug'] ) : '';
		$out['login_slug'] = $slug ? $slug : $d['login_slug'];

		// Textarea.
		$out['spam_keywords']    = isset( $input['spam_keywords'] ) ? sanitize_textarea_field( $input['spam_keywords'] ) : $d['spam_keywords'];
		$out['fw_whitelist_ips'] = isset( $input['fw_whitelist_ips'] ) ? sanitize_textarea_field( $input['fw_whitelist_ips'] ) : '';

		// Vai trò 2FA.
		$roles = isset( $input['2fa_roles'] ) && is_array( $input['2fa_roles'] ) ? array_map( 'sanitize_key', $input['2fa_roles'] ) : array();
		$out['2fa_roles'] = $roles;

		// Cảnh báo nếu bật 2FA mà email không gửi được? -> để người dùng tự kiểm, không chặn.

		return $out;
	}

	/**
	 * Tiện ích in checkbox.
	 *
	 * @param string $key   Khóa.
	 * @param string $label Nhãn.
	 * @param string $desc  Mô tả.
	 */
	private function checkbox( $key, $label, $desc = '' ) {
		$val = ! empty( $this->s[ $key ] );
		echo '<label style="display:block;margin:6px 0;">';
		echo '<input type="checkbox" name="' . esc_attr( MT_SEC_OPTION . '[' . $key . ']' ) . '" value="1" ' . checked( $val, true, false ) . '> ';
		echo '<strong>' . esc_html( $label ) . '</strong>';
		if ( $desc ) {
			echo '<br><span class="description" style="margin-left:24px;">' . wp_kses_post( $desc ) . '</span>';
		}
		echo '</label>';
	}

	/**
	 * Tiện ích in input số.
	 *
	 * @param string $key   Khóa.
	 * @param string $label Nhãn.
	 * @param string $desc  Mô tả.
	 */
	private function number( $key, $label, $desc = '' ) {
		$val = isset( $this->s[ $key ] ) ? (int) $this->s[ $key ] : 0;
		echo '<p><label><strong>' . esc_html( $label ) . '</strong><br>';
		echo '<input type="number" min="0" name="' . esc_attr( MT_SEC_OPTION . '[' . $key . ']' ) . '" value="' . esc_attr( $val ) . '" class="small-text"></label>';
		if ( $desc ) {
			echo ' <span class="description">' . esc_html( $desc ) . '</span>';
		}
		echo '</p>';
	}

	/**
	 * Render trang cài đặt.
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$this->s = get_option( MT_SEC_OPTION, MT_Security::default_settings() );
		$this->s = wp_parse_args( $this->s, MT_Security::default_settings() );

		$fw_blocked = (int) get_option( 'mt_sec_fw_blocked', 0 );
		$bf_locks   = (int) get_option( 'mt_sec_bf_locks', 0 );
		$login_url  = home_url( ( $this->s['login_slug'] ? $this->s['login_slug'] : 'secure-login' ) . '/' );
		?>
		<div class="wrap mt-sec-wrap">
			<h1><span class="dashicons dashicons-shield-alt"></span> MT Security</h1>

			<div class="mt-sec-stats" style="display:flex;gap:16px;margin:16px 0;">
				<div class="mt-sec-card" style="background:#fff;border:1px solid #ddd;padding:12px 18px;border-radius:8px;">
					<div style="font-size:24px;font-weight:700;"><?php echo esc_html( number_format_i18n( $fw_blocked ) ); ?></div>
					<div class="description"><?php esc_html_e( 'Request độc hại đã chặn', 'mt-security' ); ?></div>
				</div>
				<div class="mt-sec-card" style="background:#fff;border:1px solid #ddd;padding:12px 18px;border-radius:8px;">
					<div style="font-size:24px;font-weight:700;"><?php echo esc_html( number_format_i18n( $bf_locks ) ); ?></div>
					<div class="description"><?php esc_html_e( 'Lượt khóa IP brute-force', 'mt-security' ); ?></div>
				</div>
			</div>

			<?php if ( ! empty( $this->s['custom_login'] ) ) : ?>
				<div class="notice notice-warning inline">
					<p>
						<strong><?php esc_html_e( 'Đường dẫn đăng nhập của bạn:', 'mt-security' ); ?></strong>
						<code><?php echo esc_html( $login_url ); ?></code>
						— <?php esc_html_e( 'Hãy lưu lại! wp-login.php và wp-admin sẽ trả về 404 với khách.', 'mt-security' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<form method="post" action="options.php">
				<?php settings_fields( 'mt_security_group' ); ?>

				<h2 class="title"><?php esc_html_e( '1. Tổng quan module', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->checkbox( 'firewall', __( 'Tường lửa (WAF)', 'mt-security' ), __( 'Chặn SQL Injection, XSS, dò file nhạy cảm, bot quét lỗ hổng.', 'mt-security' ) );
					$this->checkbox( 'hardening', __( 'Gia cố hệ thống', 'mt-security' ), __( 'Ẩn version, tắt XML-RPC, chặn dò user.', 'mt-security' ) );
					$this->checkbox( 'antispam', __( 'Chống spam bình luận', 'mt-security' ) );
					$this->checkbox( 'brute_force', __( 'Khóa IP khi đăng nhập sai nhiều lần', 'mt-security' ) );
					$this->checkbox( 'custom_login', __( 'Đổi đường dẫn đăng nhập', 'mt-security' ), __( '<strong>Lưu ý:</strong> Ghi nhớ đường dẫn mới trước khi đăng xuất!', 'mt-security' ) );
					$this->checkbox( 'two_factor', __( 'Đăng nhập 2 lớp (2FA)', 'mt-security' ), __( 'Bằng app xác thực (TOTP) hoặc email, kèm mã dự phòng.', 'mt-security' ) );
					$this->checkbox( 'user_guard', __( 'Bảo vệ tài khoản (chặn đăng ký & admin ẩn)', 'mt-security' ) );
					?>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '2. Gia cố hệ thống', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->checkbox( 'hide_wp_version', __( 'Ẩn phiên bản WordPress', 'mt-security' ) );
					$this->checkbox( 'disable_xmlrpc', __( 'Tắt XML-RPC & Pingback', 'mt-security' ) );
					$this->checkbox( 'disable_file_edit', __( 'Cấm sửa file theme/plugin trong admin', 'mt-security' ) );
					$this->checkbox( 'block_user_enum', __( 'Chặn dò username (?author=N)', 'mt-security' ) );
					$this->checkbox( 'disable_rest_users', __( 'Ẩn danh sách user qua REST API', 'mt-security' ) );
					$this->checkbox( 'remove_readme', __( 'Chặn readme.html & license.txt', 'mt-security' ) );
					?>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '3. Chống spam bình luận', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->checkbox( 'spam_honeypot', __( 'Bẫy honeypot + kiểm tra thời gian gửi', 'mt-security' ) );
					$this->number( 'spam_min_time', __( 'Thời gian tối thiểu để gửi (giây)', 'mt-security' ), __( 'Gửi nhanh hơn mức này bị coi là bot.', 'mt-security' ) );
					$this->number( 'spam_max_links', __( 'Số link tối đa cho phép', 'mt-security' ) );
					$this->checkbox( 'spam_block_keywords', __( 'Lọc từ khóa spam', 'mt-security' ) );
					?>
					<p><label><strong><?php esc_html_e( 'Danh sách từ khóa cấm (mỗi dòng một từ):', 'mt-security' ); ?></strong><br>
					<textarea name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[spam_keywords]" rows="5" class="large-text code"><?php echo esc_textarea( $this->s['spam_keywords'] ); ?></textarea></label></p>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '4. Chống brute-force (khóa IP)', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->number( 'bf_max_attempts', __( 'Số lần sai tối đa', 'mt-security' ), __( 'Mặc định 3.', 'mt-security' ) );
					$this->number( 'bf_lockout_minutes', __( 'Thời gian khóa (phút)', 'mt-security' ) );
					$this->number( 'bf_long_threshold', __( 'Số lần bị khóa trước khi khóa dài', 'mt-security' ) );
					$this->number( 'bf_long_lockout', __( 'Thời gian khóa dài (giờ)', 'mt-security' ), __( '0 = không dùng khóa dài.', 'mt-security' ) );
					?>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '5. Đổi đường dẫn đăng nhập', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<p><label><strong><?php esc_html_e( 'Slug đăng nhập', 'mt-security' ); ?></strong><br>
					<?php echo esc_html( trailingslashit( home_url() ) ); ?><input type="text" name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[login_slug]" value="<?php echo esc_attr( $this->s['login_slug'] ); ?>" class="regular-text"></label></p>
					<p class="description"><?php esc_html_e( 'Chỉ dùng chữ thường, số và dấu gạch ngang. VD: secure-login, my-admin...', 'mt-security' ); ?></p>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '6. Đăng nhập 2 lớp (2FA)', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<p><strong><?php esc_html_e( 'Phương thức xác thực:', 'mt-security' ); ?></strong><br>
					<?php $method = isset( $this->s['2fa_method'] ) ? $this->s['2fa_method'] : 'totp'; ?>
					<label style="margin-right:18px;"><input type="radio" name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[2fa_method]" value="totp" <?php checked( $method, 'totp' ); ?>> <?php esc_html_e( 'App xác thực (TOTP) — khuyên dùng', 'mt-security' ); ?></label>
					<label><input type="radio" name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[2fa_method]" value="email" <?php checked( $method, 'email' ); ?>> <?php esc_html_e( 'Mã OTP qua email', 'mt-security' ); ?></label></p>
					<p class="description"><?php esc_html_e( 'TOTP: mỗi user tự thiết lập trong trang Hồ sơ (Users → Profile). Email: cần website gửi được mail (nên cài SMTP).', 'mt-security' ); ?></p>
					<hr>
					<p><strong><?php esc_html_e( 'Áp dụng 2FA cho vai trò:', 'mt-security' ); ?></strong></p>
					<?php
					$all_roles = function_exists( 'get_editable_roles' ) ? get_editable_roles() : wp_roles()->roles;
					$selected  = isset( $this->s['2fa_roles'] ) ? (array) $this->s['2fa_roles'] : array();
					foreach ( $all_roles as $role_key => $role ) {
						$name = isset( $role['name'] ) ? $role['name'] : $role_key;
						echo '<label style="display:inline-block;margin:4px 16px 4px 0;">';
						echo '<input type="checkbox" name="' . esc_attr( MT_SEC_OPTION ) . '[2fa_roles][]" value="' . esc_attr( $role_key ) . '" ' . checked( in_array( $role_key, $selected, true ), true, false ) . '> ';
						echo esc_html( translate_user_role( $name ) );
						echo '</label>';
					}
					$this->number( '2fa_code_ttl', __( 'Hiệu lực mã OTP email (phút)', 'mt-security' ) );
					$this->number( '2fa_backup_count', __( 'Số mã dự phòng cấp cho mỗi user', 'mt-security' ) );
					?>
				</td></tr></table>

				<h2 class="title"><?php esc_html_e( '7. Tường lửa (WAF)', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->checkbox( 'fw_block_bad_agents', __( 'Chặn bot/công cụ quét lỗ hổng', 'mt-security' ) );
					$this->checkbox( 'fw_block_sqli', __( 'Chặn SQL Injection', 'mt-security' ) );
					$this->checkbox( 'fw_block_xss', __( 'Chặn XSS / Path Traversal / LFI', 'mt-security' ) );
					$this->checkbox( 'fw_protect_files', __( 'Bảo vệ file nhạy cảm (.env, .git, wp-config...)', 'mt-security' ) );
					$this->checkbox( 'fw_trust_proxy', __( 'Đang dùng Cloudflare/Proxy tin cậy', 'mt-security' ), __( 'Bật để lấy đúng IP khách từ header proxy.', 'mt-security' ) );
					?>
					<p><label><strong><?php esc_html_e( 'IP tin cậy (bỏ qua tường lửa) — mỗi dòng một IP:', 'mt-security' ); ?></strong><br>
					<textarea name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[fw_whitelist_ips]" rows="4" class="large-text code" placeholder="VD: 123.45.67.89"><?php echo esc_textarea( $this->s['fw_whitelist_ips'] ); ?></textarea></label></p>
					<p class="description"><?php esc_html_e( 'IP hiện tại của bạn:', 'mt-security' ); ?> <code><?php echo esc_html( MT_Security::get_ip( ! empty( $this->s['fw_trust_proxy'] ) ) ); ?></code></p>
				</td></tr></table>

				<h2 class="title" id="user-guard"><?php esc_html_e( '8. Bảo vệ tài khoản', 'mt-security' ); ?></h2>
				<table class="form-table"><tr><td>
					<?php
					$this->checkbox( 'block_registration', __( 'Chặn tạo tài khoản mới (tắt đăng ký công khai)', 'mt-security' ), __( 'Lưu ý: nếu website bán hàng/thành viên cho khách tự đăng ký (WooCommerce...), hãy để TẮT.', 'mt-security' ) );
					$this->checkbox( 'guard_admins', __( 'Giám sát & phát hiện tài khoản quản trị ẩn', 'mt-security' ) );
					$this->checkbox( 'block_new_admins', __( 'Chặn cứng: tự động hạ quyền admin lạ ngay khi được tạo', 'mt-security' ), __( 'Admin mới sẽ bị hạ về Subscriber cho tới khi bạn duyệt ở bảng dưới.', 'mt-security' ) );
					?>
					<p><label><strong><?php esc_html_e( 'Email nhận cảnh báo', 'mt-security' ); ?></strong><br>
					<input type="email" name="<?php echo esc_attr( MT_SEC_OPTION ); ?>[guard_alert_email]" value="<?php echo esc_attr( $this->s['guard_alert_email'] ); ?>" class="regular-text" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>"></label></p>
				</td></tr></table>

				<?php submit_button( __( 'Lưu thay đổi', 'mt-security' ) ); ?>
			</form>

			<?php $this->render_admin_report(); ?>
		</div>
		<?php
	}

	/**
	 * Bảng liệt kê tài khoản quản trị (kể cả admin bị ẩn).
	 */
	private function render_admin_report() {
		if ( empty( $this->s['user_guard'] ) || empty( $this->s['guard_admins'] ) ) {
			return;
		}
		require_once MT_SEC_DIR . 'includes/class-mt-user-guard.php';
		$guard  = new MT_Sec_User_Guard( $this->s );
		$report = $guard->get_admin_report();
		$me     = get_current_user_id();
		?>
		<h2><?php esc_html_e( 'Danh sách tài khoản quản trị', 'mt-security' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Truy vấn trực tiếp cơ sở dữ liệu — admin bị malware giấu khỏi trang Users vẫn hiện ở đây.', 'mt-security' ); ?></p>
		<table class="widefat striped" style="max-width:960px;">
			<thead><tr>
				<th><?php esc_html_e( 'Tài khoản', 'mt-security' ); ?></th>
				<th><?php esc_html_e( 'Email', 'mt-security' ); ?></th>
				<th><?php esc_html_e( 'Ngày tạo', 'mt-security' ); ?></th>
				<th><?php esc_html_e( 'Trạng thái', 'mt-security' ); ?></th>
				<th><?php esc_html_e( 'Hành động', 'mt-security' ); ?></th>
			</tr></thead>
			<tbody>
			<?php foreach ( $report as $r ) : ?>
				<tr<?php echo ( ! $r['authorized'] || $r['hidden'] ) ? ' style="background:#fff2f2;"' : ''; ?>>
					<td><strong><?php echo esc_html( $r['login'] ); ?></strong><?php echo ( $r['id'] === $me ) ? ' <em>(' . esc_html__( 'bạn', 'mt-security' ) . ')</em>' : ''; ?></td>
					<td><?php echo esc_html( $r['email'] ); ?></td>
					<td><?php echo esc_html( mysql2date( 'd/m/Y', $r['registered'] ) ); ?></td>
					<td>
						<?php if ( $r['hidden'] ) : ?>
							<span style="color:#b32d2e;font-weight:600;">⚠ <?php esc_html_e( 'ĐANG BỊ ẨN', 'mt-security' ); ?></span><br>
						<?php endif; ?>
						<?php if ( $r['authorized'] ) : ?>
							<span style="color:#227a22;">✔ <?php esc_html_e( 'Đã duyệt', 'mt-security' ); ?></span>
						<?php else : ?>
							<span style="color:#b32d2e;font-weight:600;">✖ <?php esc_html_e( 'Chưa duyệt', 'mt-security' ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<?php if ( ! $r['authorized'] ) : ?>
							<a class="button button-small button-primary" href="<?php echo esc_url( MT_Sec_User_Guard::action_url( 'authorize', $r['id'] ) ); ?>"><?php esc_html_e( 'Duyệt', 'mt-security' ); ?></a>
						<?php endif; ?>
						<?php if ( $r['id'] !== $me ) : ?>
							<a class="button button-small" href="<?php echo esc_url( MT_Sec_User_Guard::action_url( 'revoke', $r['id'] ) ); ?>" onclick="return confirm('<?php esc_attr_e( 'Gỡ quyền admin của tài khoản này?', 'mt-security' ); ?>');"><?php esc_html_e( 'Gỡ quyền', 'mt-security' ); ?></a>
							<a class="button button-small" style="color:#b32d2e;" href="<?php echo esc_url( MT_Sec_User_Guard::action_url( 'delete', $r['id'] ) ); ?>" onclick="return confirm('<?php esc_attr_e( 'XÓA HẲN tài khoản này? Không thể hoàn tác.', 'mt-security' ); ?>');"><?php esc_html_e( 'Xóa', 'mt-security' ); ?></a>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}
}
