//! Collecting UR parts from a camera, a file, or stdin.
//!
//! The signature response from a cold wallet is a ~7.2 KB payload split into
//! dozens of fountain-coded UR fragments cycling on the device screen. Frames
//! may be observed in any order and with gaps; `quantus_ur::is_complete` is the
//! authoritative completion check.

use crate::error::{QuantusError, Result};
use std::{path::PathBuf, time::Duration};

/// Where to read UR parts from.
#[derive(Debug, Clone)]
pub enum UrSource {
	/// Scan the animated QR with a local camera.
	#[cfg(feature = "camera")]
	Camera { index: u32 },
	/// Read UR parts (one per line) from a file, polling until it exists and
	/// holds a complete set. Enables scripted/headless flows.
	File(PathBuf),
	/// Read UR parts from stdin, one per line, until complete or EOF.
	StdinLines,
}

/// Parse the `seq-total` marker out of a multi-part UR string
/// (`ur:quantus-sign-request/12-37/…` → `(12, 37)`). Single-part URs have no
/// marker. Used only for progress display; completion is decided by the
/// fountain decoder.
pub(crate) fn ur_progress(part: &str) -> Option<(u32, u32)> {
	let mut segments = part.split('/');
	let seq = segments.nth(1)?;
	let (a, b) = seq.split_once('-')?;
	Some((a.parse().ok()?, b.parse().ok()?))
}

fn is_ur_line(line: &str) -> bool {
	let trimmed = line.trim();
	trimmed.len() > 3 && trimmed[..3].eq_ignore_ascii_case("ur:")
}

fn decode_if_complete(parts: &[String]) -> Result<Option<Vec<u8>>> {
	if parts.is_empty() || !quantus_ur::is_complete(parts) {
		return Ok(None);
	}
	let bytes = quantus_ur::decode_bytes(parts)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode UR parts: {e:?}")))?;
	Ok(Some(bytes))
}

/// Collect UR parts from `source` until the fountain decoder reports a complete
/// payload, then decode it.
pub async fn scan_ur(source: &UrSource, timeout: Duration) -> Result<Vec<u8>> {
	match source {
		#[cfg(feature = "camera")]
		UrSource::Camera { index } => camera::scan_ur_with_camera(*index, timeout).await,
		UrSource::File(path) => scan_ur_from_file(path, timeout).await,
		UrSource::StdinLines =>
			tokio::time::timeout(timeout, scan_ur_from_stdin()).await.map_err(|_| {
				QuantusError::Generic("Timed out waiting for a complete UR on stdin".to_string())
			})?,
	}
}

/// Poll `path` until it contains a complete set of UR parts (one per line).
async fn scan_ur_from_file(path: &std::path::Path, timeout: Duration) -> Result<Vec<u8>> {
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		if let Ok(content) = std::fs::read_to_string(path) {
			let parts: Vec<String> = content
				.lines()
				.filter(|l| is_ur_line(l))
				.map(|l| l.trim().to_string())
				.collect();
			if let Some(bytes) = decode_if_complete(&parts)? {
				return Ok(bytes);
			}
		}

		if tokio::time::Instant::now() >= deadline {
			return Err(QuantusError::Generic(format!(
				"Timed out waiting for a complete UR response in {}",
				path.display()
			)));
		}

		tokio::select! {
			_ = tokio::time::sleep(Duration::from_millis(500)) => {},
			_ = tokio::signal::ctrl_c() => {
				return Err(QuantusError::Generic("Aborted by user".to_string()));
			},
		}
	}
}

/// Read UR parts from stdin, one per line, until the payload is complete or EOF.
async fn scan_ur_from_stdin() -> Result<Vec<u8>> {
	crate::log_print!("Paste the UR parts (one per line); scanning stops once complete:");
	tokio::task::spawn_blocking(|| {
		use std::io::BufRead;
		let stdin = std::io::stdin();
		let mut parts: Vec<String> = Vec::new();
		for line in stdin.lock().lines() {
			let line = line?;
			if is_ur_line(&line) {
				parts.push(line.trim().to_string());
				if let Some(bytes) = decode_if_complete(&parts)? {
					return Ok(bytes);
				}
			}
		}
		Err(QuantusError::Generic(
			"Input ended before a complete UR payload was received".to_string(),
		))
	})
	.await
	.map_err(|e| QuantusError::Generic(format!("stdin reader task failed: {e}")))?
}

/// Scan a plain (non-UR) QR containing a Quantus SS58 address, as shown on the
/// receive/address screen of a Keystone device or the Quantus cold wallet app.
pub async fn scan_quantus_address(camera_index: u32) -> Result<String> {
	#[cfg(feature = "camera")]
	{
		camera::scan_address_with_camera(camera_index).await
	}
	#[cfg(not(feature = "camera"))]
	{
		let _ = camera_index;
		Err(QuantusError::Generic(
			"This build has no camera support (built without the `camera` feature). Pass the address explicitly with --address".to_string(),
		))
	}
}

#[cfg(feature = "camera")]
mod camera {
	use super::*;
	use std::{
		collections::HashSet,
		sync::{
			atomic::{AtomicBool, Ordering},
			mpsc, Arc,
		},
		time::Instant,
	};

	const PREVIEW_W: usize = 960;
	const PREVIEW_H: usize = 540;

	/// Ask for camera permission. On macOS this pops the TCC dialog (attributed
	/// to the terminal app, not `quantus`); on other platforms it's a no-op.
	fn ensure_permission() -> Result<()> {
		let (tx, rx) = mpsc::channel();
		nokhwa::nokhwa_initialize(move |granted| {
			let _ = tx.send(granted);
		});
		match rx.recv_timeout(Duration::from_secs(30)) {
			Ok(true) => Ok(()),
			Ok(false) => Err(QuantusError::Generic(
				"Camera permission denied. Grant camera access to your terminal app in System Settings > Privacy & Security > Camera, or avoid the camera with --cold-response-in <file|-> / --address".to_string(),
			)),
			Err(_) => Err(QuantusError::Generic(
				"Timed out waiting for camera permission. Approve the dialog in System Settings > Privacy & Security > Camera and retry, or avoid the camera with --cold-response-in <file|-> / --address".to_string(),
			)),
		}
	}

	fn rgb_to_luma(raw: &[u8], width: u32, height: u32) -> (usize, usize, Vec<u8>) {
		let w = width as usize;
		let h = height as usize;
		let mut luma = Vec::with_capacity(w * h);
		for px in raw.chunks_exact(3) {
			luma.push(
				((u16::from(px[0]) * 77 + u16::from(px[1]) * 150 + u16::from(px[2]) * 29) >> 8)
					as u8,
			);
		}
		(w, h, luma)
	}

	fn downscale2(luma: &[u8], w: usize, h: usize) -> Option<(usize, usize, Vec<u8>)> {
		let nw = w / 2;
		let nh = h / 2;
		if nw < 21 || nh < 21 {
			return None;
		}
		let mut out = Vec::with_capacity(nw * nh);
		for y in 0..nh {
			for x in 0..nw {
				let i = (2 * y) * w + (2 * x);
				let avg = (u16::from(luma[i]) +
					u16::from(luma[i + 1]) +
					u16::from(luma[i + w]) +
					u16::from(luma[i + w + 1])) /
					4;
				out.push(avg as u8);
			}
		}
		Some((nw, nh, out))
	}

	fn feed_decoded<T>(
		luma: &[u8],
		w: usize,
		h: usize,
		mut sink: impl FnMut(&str) -> Option<T>,
	) -> Option<T> {
		let mut run = |luma: &[u8], w: usize, h: usize, invert: bool| -> Option<T> {
			if w < 21 || h < 21 || luma.len() != w.saturating_mul(h) {
				return None;
			}
			let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
					let v = luma[y * w + x];
					if invert {
						255 - v
					} else {
						v
					}
				});
				let mut found = Vec::new();
				for grid in prepared.detect_grids() {
					if let Ok((_meta, content)) = grid.decode() {
						found.push(content);
					}
				}
				found
			}))
			.unwrap_or_default();
			for content in decoded {
				if let Some(hit) = sink(&content) {
					return Some(hit);
				}
			}
			None
		};

		if let Some(hit) = run(luma, w, h, false) {
			return Some(hit);
		}
		if let Some(hit) = run(luma, w, h, true) {
			return Some(hit);
		}
		if let Some((nw, nh, half)) = downscale2(luma, w, h) {
			if let Some(hit) = run(&half, nw, nh, false) {
				return Some(hit);
			}
			if let Some(hit) = run(&half, nw, nh, true) {
				return Some(hit);
			}
		}
		None
	}

	fn rgb_preview_u32(raw: &[u8], sw: u32, sh: u32, dw: usize, dh: usize) -> Vec<u32> {
		let mut out = vec![0u32; dw * dh];
		if sw == 0 || sh == 0 {
			return out;
		}
		for y in 0..dh {
			let sy = y * sh as usize / dh;
			for x in 0..dw {
				let sx = x * sw as usize / dw;
				let i = (sy * sw as usize + sx) * 3;
				if i + 2 < raw.len() {
					out[y * dw + x] = u32::from(raw[i]) << 16 |
						u32::from(raw[i + 1]) << 8 |
						u32::from(raw[i + 2]);
				}
			}
		}
		out
	}

	/// Grab frames at the camera's highest frame rate and decode each at native
	/// resolution. Cold-wallet UR animations run at 15–50 fps.
	fn scan_with_camera<T>(
		index: u32,
		timeout: Duration,
		stop: Arc<AtomicBool>,
		mut on_status: impl FnMut(&str),
		mut sink: impl FnMut(&str) -> Option<Result<T>>,
	) -> Result<T> {
		use nokhwa::{
			pixel_format::RgbFormat,
			utils::{CameraIndex, RequestedFormat, RequestedFormatType},
			Camera,
		};

		ensure_permission()?;

		let mut camera = Camera::new(
			CameraIndex::Index(index),
			RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate),
		)
		.map_err(|e| {
			QuantusError::Generic(format!(
				"Failed to open camera {index}: {e}. Try a different --camera-index, or avoid the camera with --cold-response-in <file|-> / --address"
			))
		})?;
		camera
			.open_stream()
			.map_err(|e| QuantusError::Generic(format!("Failed to start camera stream: {e}")))?;
		let fmt = camera.camera_format();
		crate::log_verbose!(
			"📷 Camera {}x{} @ {} fps",
			fmt.width(),
			fmt.height(),
			fmt.frame_rate()
		);
		on_status(&format!(
			"📷 Live {}x{} @ {} fps — opening preview…",
			fmt.width(),
			fmt.height(),
			fmt.frame_rate()
		));

		let mut window = minifb::Window::new(
			"Quantus camera — hold the QR in this view",
			PREVIEW_W,
			PREVIEW_H,
			minifb::WindowOptions { resize: false, ..minifb::WindowOptions::default() },
		)
		.map_err(|e| {
			crate::log_verbose!("📷 Preview window unavailable: {e}");
			e
		})
		.ok();
		if window.is_some() {
			crate::log_print!(
				"🖼️  Camera preview window opened — aim the QR so it is sharp in that view"
			);
		}

		let deadline = Instant::now() + timeout;
		let mut frames: u64 = 0;
		let result = 'scan: loop {
			if stop.load(Ordering::Relaxed) {
				break Err(QuantusError::Generic("Aborted by user".to_string()));
			}
			if Instant::now() >= deadline {
				break Err(QuantusError::Generic(
					"Timed out scanning. Keep the QR sharp in the preview window (15-25 cm, high brightness), or use --cold-response-in <file|-> / --address".to_string(),
				));
			}

			let frame = match camera.frame() {
				Ok(frame) => frame,
				Err(e) => {
					crate::log_verbose!("📷 Dropped camera frame: {e}");
					continue;
				},
			};
			let img = match frame.decode_image::<RgbFormat>() {
				Ok(img) => img,
				Err(e) => {
					crate::log_verbose!("📷 Failed to decode camera frame: {e}");
					continue;
				},
			};
			frames += 1;
			if frames == 1 || frames % 15 == 0 {
				on_status(&format!(
					"📷 Live {}x{} @ {} fps — {} frames, no QR yet",
					img.width(),
					img.height(),
					fmt.frame_rate(),
					frames
				));
			}

			if let Some(win) = window.as_mut() {
				if !win.is_open() {
					window = None;
				} else {
					let buf = rgb_preview_u32(
						img.as_raw(),
						img.width(),
						img.height(),
						PREVIEW_W,
						PREVIEW_H,
					);
					if let Err(e) = win.update_with_buffer(&buf, PREVIEW_W, PREVIEW_H) {
						crate::log_verbose!("📷 Preview update failed: {e}");
						window = None;
					}
				}
			}

			let (w, h, luma) = rgb_to_luma(img.as_raw(), img.width(), img.height());
			if luma.len() != w.saturating_mul(h) {
				continue;
			}
			if let Some(result) = feed_decoded(&luma, w, h, |content| sink(content)) {
				break 'scan result;
			}
		};

		let _ = camera.stop_stream();
		result
	}

	/// Drive the blocking camera loop from async code, aborting on Ctrl-C.
	async fn run_scan<T: Send + 'static>(
		index: u32,
		timeout: Duration,
		on_status: impl FnMut(&str) + Send + 'static,
		sink: impl FnMut(&str) -> Option<Result<T>> + Send + 'static,
	) -> Result<T> {
		let stop = Arc::new(AtomicBool::new(false));
		let stop_flag = stop.clone();
		let handle = tokio::task::spawn_blocking(move || {
			scan_with_camera(index, timeout, stop_flag, on_status, sink)
		});

		tokio::select! {
			result = handle => result
				.map_err(|e| QuantusError::Generic(format!("Camera task failed: {e}")))?,
			_ = tokio::signal::ctrl_c() => {
				stop.store(true, Ordering::Relaxed);
				println!();
				Err(QuantusError::Generic("Aborted by user".to_string()))
			},
		}
	}

	fn scan_spinner(message: &str) -> indicatif::ProgressBar {
		use indicatif::{ProgressBar, ProgressStyle};
		let pb = ProgressBar::new_spinner();
		pb.set_style(
			ProgressStyle::default_spinner()
				.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
				.template("{spinner:.cyan} {msg}")
				.unwrap(),
		);
		pb.set_message(message.to_string());
		pb.enable_steady_tick(Duration::from_millis(120));
		pb
	}

	/// Scan an animated (or static) UR from the camera until the fountain
	/// decoder has a complete payload.
	pub(super) async fn scan_ur_with_camera(index: u32, timeout: Duration) -> Result<Vec<u8>> {
		let spinner = scan_spinner("📷 Point the camera at the QR on the cold wallet…");
		let status = spinner.clone();
		let progress = spinner.clone();

		let mut seen: HashSet<String> = HashSet::new();
		let mut parts: Vec<String> = Vec::new();
		let mut total: Option<u32> = None;

		let result = run_scan(
			index,
			timeout,
			move |msg| status.set_message(msg.to_string()),
			move |content| {
				if !is_ur_line(content) {
					return None;
				}
				let part = content.trim().to_string();
				if !seen.insert(part.clone()) {
					return None;
				}
				if let Some((_, t)) = ur_progress(&part) {
					total = Some(t);
				}
				parts.push(part);
				let of_total = total.map(|t| format!(" (sequence of {t})")).unwrap_or_default();
				progress.set_message(format!(
					"📷 Captured {} UR part{}{}…",
					parts.len(),
					if parts.len() == 1 { "" } else { "s" },
					of_total
				));
				decode_if_complete(&parts).transpose()
			},
		)
		.await;

		spinner.finish_and_clear();
		result
	}

	/// Scan a plain QR until it contains a valid Quantus (prefix 189) address.
	pub(super) async fn scan_address_with_camera(index: u32) -> Result<String> {
		use sp_core::crypto::{AccountId32, Ss58Codec};

		let spinner = scan_spinner("📷 Point the camera at the address QR…");
		let status = spinner.clone();
		let progress = spinner.clone();

		let result = run_scan(
			index,
			Duration::from_secs(120),
			move |msg| status.set_message(msg.to_string()),
			move |content| {
				let trimmed = content.trim();
				match AccountId32::from_ss58check_with_version(trimmed) {
					Ok((_, format))
						if format == crate::cli::address_format::quantus_ss58_format() =>
						Some(Ok(trimmed.to_string())),
					_ => {
						progress.set_message(format!(
							"📷 Saw a QR that is not a Quantus address ({}…) — keep looking…",
							trimmed.chars().take(16).collect::<String>()
						));
						None
					},
				}
			},
		)
		.await;

		spinner.finish_and_clear();
		result
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		fn render_qr_luma(data: &str, invert: bool) -> (usize, usize, Vec<u8>) {
			use qrcode::{types::Color, QrCode};
			let code = QrCode::new(data.as_bytes()).expect("qr");
			const SCALE: usize = 8;
			let qz = 4 * SCALE;
			let inner = code.width() * SCALE;
			let w = inner + qz * 2;
			let bg = if invert { 0u8 } else { 255u8 };
			let mut luma = vec![bg; w * w];
			for y in 0..code.width() {
				for x in 0..code.width() {
					let dark = code[(x, y)] == Color::Dark;
					let v = match (dark, invert) {
						(true, false) | (false, true) => 0u8,
						_ => 255,
					};
					for dy in 0..SCALE {
						for dx in 0..SCALE {
							luma[(y * SCALE + qz + dy) * w + (x * SCALE + qz + dx)] = v;
						}
					}
				}
			}
			(w, w, luma)
		}

		#[test]
		fn decodes_standard_and_inverted_qr() {
			let data = "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2";
			let collect = |luma: &[u8], w: usize, h: usize| {
				let mut found = Vec::new();
				feed_decoded(luma, w, h, |s| {
					found.push(s.to_string());
					None::<()>
				});
				found
			};
			let (w, h, normal) = render_qr_luma(data, false);
			assert!(
				collect(&normal, w, h).iter().any(|s| s == data),
				"standard polarity: {:?}",
				collect(&normal, w, h)
			);
			let (w, h, inverted) = render_qr_luma(data, true);
			assert!(
				collect(&inverted, w, h).iter().any(|s| s == data),
				"inverted polarity (cold-wallet address QR): {:?}",
				collect(&inverted, w, h)
			);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ur_progress_multipart() {
		assert_eq!(ur_progress("ur:quantus-sign-request/12-37/lpamchcfatttcy…"), Some((12, 37)));
		assert_eq!(ur_progress("UR:QUANTUS-SIGN-REQUEST/412-37/LPAM…"), Some((412, 37)));
	}

	#[test]
	fn test_ur_progress_single_part() {
		// Single-part URs carry the bytewords directly in segment 1
		assert_eq!(ur_progress("ur:quantus-sign-request/hdcxlkadaeae"), None);
		assert_eq!(ur_progress("not-a-ur"), None);
	}

	#[test]
	fn test_is_ur_line() {
		assert!(is_ur_line("ur:quantus-sign-request/1-3/abc"));
		assert!(is_ur_line("  UR:QUANTUS-SIGN-REQUEST/HDCX  "));
		assert!(!is_ur_line("ur:"));
		assert!(!is_ur_line("# comment"));
		assert!(!is_ur_line(""));
	}

	#[tokio::test]
	async fn test_scan_ur_from_file_roundtrip() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("parts.ur");
		let payload: Vec<u8> = (0..=255u8).cycle().take(7219).collect();
		let parts = quantus_ur::encode_bytes(&payload).unwrap();
		assert!(parts.len() > 1, "7219-byte payload must be multi-part");
		std::fs::write(&path, parts.join("\n")).unwrap();

		let decoded = scan_ur(&UrSource::File(path), Duration::from_secs(5)).await.expect("decode");
		assert_eq!(decoded, payload);
	}

	#[tokio::test]
	async fn test_scan_ur_from_file_times_out() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("never-written.ur");
		let result = scan_ur(&UrSource::File(path), Duration::from_millis(100)).await;
		assert!(result.is_err());
	}
}
