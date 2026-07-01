<?php
/**
 * Chống spam bình luận: honeypot, kiểm tra thời gian gửi, giới hạn link, lọc từ khóa.
 * Không dùng dịch vụ ngoài -> không phụ thuộc & không làm chậm.
 *
 * @package MT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MT_Sec_Antispam {

	/**
	 * Cấu hình.
	 *
	 * @var array
	 */
	private $s;

	/**
	 * Tên trường honeypot (cố định để JS/CSS ẩn dễ).
	 *
	 * @var string
	 */
	private $hp_field = 'mt_sec_hp';

	/**
	 * Tên trường timestamp.
	 *
	 * @var string
	 */
	private $ts_field = 'mt_sec_ts';

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
		// Thêm trường ẩn vào form bình luận.
		if ( ! empty( $this->s['spam_honeypot'] ) ) {
			add_action( 'comment_form_after_fields', array( $this, 'add_fields' ) );
			add_action( 'comment_form_logged_in_after', array( $this, 'add_fields' ) );
		}
		// Kiểm tra trước khi WP lưu bình luận.
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 1 );
	}

	/**
	 * In trường honeypot + timestamp.
	 * Honeypot ẩn bằng inline-style + aria-hidden, bot điền -> chặn.
	 */
	public function add_fields() {
		$ts = time();
		echo '<p style="display:none !important;visibility:hidden;position:absolute;left:-9999px;" aria-hidden="true">';
		echo '<label>Để trống ô này nếu bạn là con người: ';
		echo '<input type="text" name="' . esc_attr( $this->hp_field ) . '" value="" autocomplete="off" tabindex="-1"></label>';
		echo '</p>';
		echo '<input type="hidden" name="' . esc_attr( $this->ts_field ) . '" value="' . esc_attr( $ts ) . '">';
	}

	/**
	 * Kiểm tra bình luận.
	 *
	 * @param array $commentdata Dữ liệu bình luận.
	 * @return array
	 */
	public function check_comment( $commentdata ) {
		// Bỏ qua người đã đăng nhập có quyền (trừ subscriber) để không cản trở.
		if ( is_user_logged_in() && current_user_can( 'moderate_comments' ) ) {
			return $commentdata;
		}

		// Chỉ áp dụng cho comment thường (không pingback/trackback đã bị tắt riêng).
		$type = isset( $commentdata['comment_type'] ) ? $commentdata['comment_type'] : '';
		if ( '' !== $type && 'comment' !== $type ) {
			return $commentdata;
		}

		// 1) Honeypot.
		if ( ! empty( $this->s['spam_honeypot'] ) ) {
			if ( ! empty( $_POST[ $this->hp_field ] ) ) {
				$this->reject();
			}
			// 2) Thời gian điền form.
			$min = (int) $this->s['spam_min_time'];
			if ( $min > 0 && isset( $_POST[ $this->ts_field ] ) ) {
				$elapsed = time() - (int) $_POST[ $this->ts_field ];
				if ( $elapsed < $min ) {
					$this->reject();
				}
			}
		}

		$content = isset( $commentdata['comment_content'] ) ? $commentdata['comment_content'] : '';

		// 3) Giới hạn số link.
		$max_links = (int) $this->s['spam_max_links'];
		if ( $max_links >= 0 ) {
			$link_count = preg_match_all( '#https?://#i', $content, $m );
			if ( $link_count > $max_links ) {
				$this->reject( __( 'Bình luận chứa quá nhiều liên kết.', 'mt-security' ) );
			}
		}

		// 4) Lọc từ khóa spam.
		if ( ! empty( $this->s['spam_block_keywords'] ) && ! empty( $this->s['spam_keywords'] ) ) {
			$haystack = strtolower(
				$content . ' ' .
				( isset( $commentdata['comment_author'] ) ? $commentdata['comment_author'] : '' ) . ' ' .
				( isset( $commentdata['comment_author_url'] ) ? $commentdata['comment_author_url'] : '' )
			);
			$keywords = preg_split( '/[\r\n]+/', strtolower( $this->s['spam_keywords'] ) );
			foreach ( $keywords as $kw ) {
				$kw = trim( $kw );
				if ( '' !== $kw && false !== strpos( $haystack, $kw ) ) {
					$this->reject();
				}
			}
		}

		return $commentdata;
	}

	/**
	 * Từ chối bình luận.
	 *
	 * @param string $message Thông báo.
	 */
	private function reject( $message = '' ) {
		if ( '' === $message ) {
			$message = __( 'Bình luận của bạn bị từ chối vì nghi ngờ spam.', 'mt-security' );
		}
		wp_die(
			esc_html( $message ),
			esc_html__( 'Bình luận bị chặn', 'mt-security' ),
			array( 'response' => 403, 'back_link' => true )
		);
	}
}
