<?php
/**
 * Dọn dẹp khi gỡ plugin.
 *
 * @package MT_Security
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'mt_security_settings' );
delete_option( 'mt_sec_fw_blocked' );
delete_option( 'mt_sec_bf_locks' );
delete_option( 'mt_sec_blocked_regs' );
delete_option( 'mt_sec_blocked_admins' );
delete_option( 'mt_sec_authorized_admins' );

global $wpdb;

// Xóa các transient brute-force/2fa còn sót.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_mt_sec_%' OR option_name LIKE '_transient_timeout_mt_sec_%'"
);

// Xóa user meta của 2FA.
delete_metadata( 'user', 0, 'mt_sec_2fa_secret', '', true );
delete_metadata( 'user', 0, 'mt_sec_2fa_active', '', true );
delete_metadata( 'user', 0, 'mt_sec_2fa_backup', '', true );
