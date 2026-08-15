//! Rendering URs as (possibly animated) QR codes in the terminal.
//!
//! Multi-part URs cycle their fragments on a timer, exactly like the mobile
//! app's animated QR widget; the fountain decoder on the cold wallet side
//! tolerates missed frames, so looping forever until the user continues is
//! correct.

use crate::error::{QuantusError, Result};
use qrcode::{types::Color, EcLevel, QrCode};
use std::{io::Write, time::Duration};

/// How long each fragment of an animated QR stays on screen. Matches the
/// 200 ms cadence of the mobile and cold wallet apps, slightly relaxed for
/// terminal redraw.
const FRAME_INTERVAL: Duration = Duration::from_millis(250);

/// Rendered QR frames, all padded to the same height so in-place redraws fully
/// overwrite the previous frame.
pub struct QrFrames {
	pub frames: Vec<String>,
	/// Number of terminal lines every frame occupies (including the counter line).
	pub height: usize,
}

/// Render one QR code as half-block characters with explicit black/white ANSI
/// colors. Explicit colors keep the QR dark-on-light regardless of the
/// terminal theme — phone scanners often reject inverted codes.
fn render_qr(data: &str) -> Result<String> {
	// EC level L: same as the mobile apps; UR fragments carry their own CRC and
	// the fountain code recovers lost frames, so denser codes beat redundancy.
	let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
		.map_err(|e| QuantusError::Generic(format!("Failed to build QR code: {e}")))?;

	let width = code.width();
	let colors = code.to_colors();
	const QUIET_ZONE: usize = 3; // modules of white border on every side

	let module = |x: isize, y: isize| -> Color {
		if x < 0 || y < 0 || x as usize >= width || y as usize >= width {
			Color::Light // quiet zone
		} else {
			colors[y as usize * width + x as usize]
		}
	};

	// Two vertical modules per character cell: '▀' with fg = upper, bg = lower.
	const RESET: &str = "\x1b[0m";

	let mut out = String::new();
	let mut y = -(QUIET_ZONE as isize);
	while y < (width + QUIET_ZONE) as isize {
		for x in -(QUIET_ZONE as isize)..(width + QUIET_ZONE) as isize {
			let upper = module(x, y);
			let lower = module(x, y + 1);
			let cell = match (upper, lower) {
				(Color::Dark, Color::Dark) => concat!("\x1b[30;40m", "▀"),
				(Color::Dark, Color::Light) => concat!("\x1b[30;107m", "▀"),
				(Color::Light, Color::Dark) => concat!("\x1b[97;40m", "▀"),
				(Color::Light, Color::Light) => concat!("\x1b[97;107m", "▀"),
			};
			out.push_str(cell);
		}
		out.push_str(RESET);
		out.push('\n');
		y += 2;
	}
	Ok(out)
}

/// Render every UR part to a QR frame, padded to uniform height.
pub fn render_ur_frames(parts: &[String]) -> Result<QrFrames> {
	if parts.is_empty() {
		return Err(QuantusError::Generic("No UR parts to render".to_string()));
	}

	let mut rendered: Vec<String> = Vec::with_capacity(parts.len());
	for part in parts {
		rendered.push(render_qr(part)?);
	}

	let max_lines = rendered.iter().map(|f| f.lines().count()).max().unwrap_or(0);
	let total = rendered.len();

	let frames: Vec<String> = rendered
		.into_iter()
		.enumerate()
		.map(|(i, mut frame)| {
			let lines = frame.lines().count();
			for _ in lines..max_lines {
				// Erase-to-end keeps stale content from a taller earlier frame away
				frame.push_str("\x1b[K\n");
			}
			if total > 1 {
				frame.push_str(&format!("   Frame {}/{}\x1b[K\n", i + 1, total));
			}
			frame
		})
		.collect();

	// +1 for the frame-counter line on animated QRs
	let height = max_lines + usize::from(total > 1);
	Ok(QrFrames { frames, height })
}

/// RAII guard: hides the terminal cursor and guarantees it comes back on every
/// exit path (Enter, Ctrl-C error return, panic unwind).
struct CursorGuard;

impl CursorGuard {
	fn new() -> Self {
		print!("\x1b[?25l");
		let _ = std::io::stdout().flush();
		CursorGuard
	}
}

impl Drop for CursorGuard {
	fn drop(&mut self) {
		print!("\x1b[?25h");
		let _ = std::io::stdout().flush();
	}
}

/// Display the QR (cycling frames if multi-part) until the user presses Enter.
/// Returns Err if the user aborts with Ctrl-C.
pub async fn display_ur_until_enter(frames: &QrFrames, caption: &str) -> Result<()> {
	let _cursor = CursorGuard::new();

	// First frame: printed normally; subsequent redraws move the cursor back up.
	print!("{}", frames.frames[0]);
	println!("{caption}");
	let _ = std::io::stdout().flush();

	let (enter_tx, mut enter_rx) = tokio::sync::oneshot::channel::<()>();
	std::thread::spawn(move || {
		let mut buf = String::new();
		let _ = std::io::stdin().read_line(&mut buf);
		let _ = enter_tx.send(());
	});

	if frames.frames.len() == 1 {
		tokio::select! {
			_ = &mut enter_rx => return Ok(()),
			_ = tokio::signal::ctrl_c() => {
				println!();
				return Err(QuantusError::Generic("Aborted by user".to_string()));
			},
		}
	}

	let mut interval = tokio::time::interval(FRAME_INTERVAL);
	interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	let mut current = 0usize;
	loop {
		tokio::select! {
			_ = interval.tick() => {
				current = (current + 1) % frames.frames.len();
				// Move up over the QR block plus the caption line, redraw in place
				print!("\x1b[{}F", frames.height + 1);
				print!("{}", frames.frames[current]);
				println!("{caption}");
				let _ = std::io::stdout().flush();
			},
			_ = &mut enter_rx => return Ok(()),
			_ = tokio::signal::ctrl_c() => {
				println!();
				return Err(QuantusError::Generic("Aborted by user".to_string()));
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_render_single_frame() {
		let parts = vec!["UR:QUANTUS-SIGN-REQUEST/HDCXLKADAEAEAEAEAE".to_string()];
		let frames = render_ur_frames(&parts).unwrap();
		assert_eq!(frames.frames.len(), 1);
		assert!(frames.height > 10);
		// No counter line on single-frame QRs
		assert!(!frames.frames[0].contains("Frame"));
	}

	#[test]
	fn test_render_multi_frame_uniform_height() {
		let payload: Vec<u8> = vec![0xAB; 1000];
		let parts = quantus_ur::encode_bytes(&payload).unwrap();
		assert!(parts.len() > 1);
		let frames = render_ur_frames(&parts).unwrap();
		let heights: std::collections::HashSet<usize> =
			frames.frames.iter().map(|f| f.lines().count()).collect();
		assert_eq!(heights.len(), 1, "all frames must have identical line counts");
		assert!(frames.frames[0].contains("Frame 1/"));
	}

	#[test]
	fn test_render_empty_fails() {
		assert!(render_ur_frames(&[]).is_err());
	}
}
