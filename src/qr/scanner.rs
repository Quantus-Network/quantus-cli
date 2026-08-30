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
	/// holds a complete set. The file is consumed (deleted) after a successful
	/// read so a later roundtrip on the same path can never pick up a stale
	/// session. Enables scripted/headless flows.
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
	// Byte-wise prefix check: QR/file input is untrusted and may start with
	// multi-byte characters, so `trimmed[..3]` could slice off a char boundary.
	let trimmed = line.trim().as_bytes();
	trimmed.len() > 3 && trimmed[..3].eq_ignore_ascii_case(b"ur:")
}

fn decode_if_complete(parts: &[String]) -> Result<Option<Vec<u8>>> {
	if parts.is_empty() || !quantus_ur::is_complete(parts) {
		return Ok(None);
	}
	let bytes = quantus_ur::decode_bytes(parts)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode UR parts: {e:?}")))?;
	Ok(Some(bytes))
}

/// The fountain decoder locks onto the first part's stream (seqLen, checksum)
/// and silently rejects every part of a different stream. A stale part
/// captured first — e.g. the previous signature still animating on the device
/// — would wedge the scan forever even though all current parts arrive. Retry
/// completion on every suffix, shortest (newest) first: when both a stale and
/// a current stream are complete in the capture, the newest must win.
fn decode_any_suffix(parts: &[String]) -> Result<Option<Vec<u8>>> {
	for start in (0..parts.len()).rev() {
		if let Some(bytes) = decode_if_complete(&parts[start..])? {
			return Ok(Some(bytes));
		}
	}
	Ok(None)
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

/// Poll `path` until it contains a complete set of UR parts (one per line),
/// then consume the file so the same path cannot serve a stale session to the
/// next roundtrip.
async fn scan_ur_from_file(path: &std::path::Path, timeout: Duration) -> Result<Vec<u8>> {
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		if let Ok(content) = std::fs::read_to_string(path) {
			let parts: Vec<String> = content
				.lines()
				.filter(|l| is_ur_line(l))
				.map(|l| l.trim().to_string())
				.collect();
			if let Some(bytes) = decode_any_suffix(&parts)? {
				if let Err(e) = std::fs::remove_file(path) {
					crate::log_print!(
						"⚠️  Could not consume UR file {}: {e} — remove it manually before the next roundtrip",
						path.display()
					);
				}
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
				if let Some(bytes) = decode_any_suffix(&parts)? {
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
			mpsc, Arc, Mutex,
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
			let buf: Vec<u8> =
				if invert { luma.iter().map(|v| 255 - v).collect() } else { luma.to_vec() };
			let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let mut hints = rxing::DecodeHints {
					PossibleFormats: Some(HashSet::from([rxing::BarcodeFormat::QR_CODE])),
					..Default::default()
				};
				rxing::helpers::detect_multiple_in_luma_with_hints(
					buf, w as u32, h as u32, &mut hints,
				)
				.unwrap_or_default()
			}))
			.unwrap_or_default();
			for result in decoded {
				if let Some(hit) = sink(result.getText()) {
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

	/// Mac cameras typically deliver NV12 (420 bi-planar). nokhwa mis-tags that
	/// as YUYV, and YUYV→RGB on NV12 bytes produces the doubled/posterized mess
	/// in the preview. Detect NV12 by buffer size and convert it correctly.
	fn frame_to_rgb(frame: &nokhwa::Buffer) -> std::result::Result<(u32, u32, Vec<u8>), String> {
		use nokhwa::{pixel_format::RgbFormat, utils::nv12_to_rgb};
		let res = frame.resolution();
		let w = res.width();
		let h = res.height();
		let raw = frame.buffer();
		let nv12_len = (w as usize).saturating_mul(h as usize).saturating_mul(3) / 2;
		let rgb = if raw.len() == nv12_len {
			nv12_to_rgb(res, raw, false).map_err(|e| format!("{e}"))?
		} else {
			frame
				.decode_image::<RgbFormat>()
				.map(|img| img.into_raw())
				.map_err(|e| format!("{e}"))?
		};
		let expected = (w as usize).saturating_mul(h as usize).saturating_mul(3);
		if rgb.len() != expected {
			return Err(format!(
				"RGB size {} != {}x{}x3 (src {:?}, raw {})",
				rgb.len(),
				w,
				h,
				frame.source_frame_format(),
				raw.len()
			));
		}
		Ok((w, h, rgb))
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
	/// Preview pixels are published for the main-thread window; NSWindow must
	/// not be created here (tokio blocking pool is not the macOS main thread).
	fn scan_with_camera<T>(
		index: u32,
		timeout: Duration,
		stop: Arc<AtomicBool>,
		preview: Arc<Mutex<Option<Vec<u32>>>>,
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
			"📷 Live {}x{} @ {} fps — waiting for QR…",
			fmt.width(),
			fmt.height(),
			fmt.frame_rate()
		));

		let deadline = Instant::now() + timeout;
		let mut frames: u64 = 0;
		let result = 'scan: loop {
			if stop.load(Ordering::Relaxed) {
				break Err(QuantusError::Generic("Aborted by user".to_string()));
			}
			if Instant::now() >= deadline {
				break Err(QuantusError::Generic(
					"Timed out scanning. Keep the QR large and steady in the preview window (high screen brightness helps), or use --cold-response-in <file|-> / --address".to_string(),
				));
			}

			let frame = match camera.frame() {
				Ok(frame) => frame,
				Err(e) => {
					crate::log_verbose!("📷 Dropped camera frame: {e}");
					continue;
				},
			};
			let (img_w, img_h, rgb) = match frame_to_rgb(&frame) {
				Ok(rgb) => rgb,
				Err(e) => {
					crate::log_verbose!("📷 Failed to decode camera frame: {e}");
					continue;
				},
			};
			frames += 1;
			if frames == 1 {
				crate::log_verbose!(
					"📷 Frame format {:?} raw {} bytes → RGB {}x{}",
					frame.source_frame_format(),
					frame.buffer().len(),
					img_w,
					img_h
				);
			}
			if frames == 1 || frames.is_multiple_of(15) {
				on_status(&format!(
					"📷 Live {img_w}x{img_h} @ {} fps — {frames} frames scanned",
					fmt.frame_rate()
				));
			}

			if let Ok(mut slot) = preview.lock() {
				*slot = Some(rgb_preview_u32(&rgb, img_w, img_h, PREVIEW_W, PREVIEW_H));
			}

			let (w, h, luma) = rgb_to_luma(&rgb, img_w, img_h);
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
	/// The preview window is created and pumped on this task (the tokio
	/// `block_on` / process main thread) so macOS AppKit is not touched off-main.
	async fn run_scan<T: Send + 'static>(
		index: u32,
		timeout: Duration,
		on_status: impl FnMut(&str) + Send + 'static,
		sink: impl FnMut(&str) -> Option<Result<T>> + Send + 'static,
	) -> Result<T> {
		let stop = Arc::new(AtomicBool::new(false));
		let stop_flag = stop.clone();
		let preview = Arc::new(Mutex::new(None));
		let preview_cam = preview.clone();
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

		let mut handle = tokio::task::spawn_blocking(move || {
			scan_with_camera(index, timeout, stop_flag, preview_cam, on_status, sink)
		});
		// AppKit draws asynchronously; keep the last buffer alive so the view
		// never paints a freed pointer (that flashed as garbage).
		let mut displayed = vec![0u32; PREVIEW_W * PREVIEW_H];

		loop {
			tokio::select! {
				result = &mut handle => {
					return result
						.map_err(|e| QuantusError::Generic(format!("Camera task failed: {e}")))?;
				},
				_ = tokio::time::sleep(Duration::from_millis(16)) => {
					if let Some(win) = window.as_mut() {
						if !win.is_open() {
							window = None;
						} else {
							if let Some(buf) = preview.lock().ok().and_then(|mut slot| slot.take())
							{
								displayed = buf;
							}
							if let Err(e) =
								win.update_with_buffer(&displayed, PREVIEW_W, PREVIEW_H)
							{
								crate::log_verbose!("📷 Preview update failed: {e}");
								window = None;
							}
						}
					}
				},
				_ = tokio::signal::ctrl_c() => {
					stop.store(true, Ordering::Relaxed);
					println!();
					return Err(QuantusError::Generic("Aborted by user".to_string()));
				},
			}
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

	#[derive(Default)]
	struct UrCapture {
		parts: Vec<String>,
		seen: HashSet<String>,
		seqs: HashSet<u32>,
		total: Option<u32>,
	}

	/// Scan an animated (or static) UR from the camera until the fountain
	/// decoder has a complete payload. Every captured part is printed as a
	/// persistent line (the live status stays on the spinner and never
	/// overwrites capture progress), and an incomplete scan reports exactly
	/// which fragments are still missing.
	pub(super) async fn scan_ur_with_camera(index: u32, timeout: Duration) -> Result<Vec<u8>> {
		let spinner = scan_spinner("📷 Point the camera at the QR on the cold wallet…");
		let status = spinner.clone();
		let progress = spinner.clone();
		let state = Arc::new(Mutex::new(UrCapture::default()));
		let status_state = state.clone();
		let sink_state = state.clone();

		let result = run_scan(
			index,
			timeout,
			move |msg| {
				let no_parts_yet =
					status_state.lock().map(|st| st.parts.is_empty()).unwrap_or(false);
				if no_parts_yet {
					status.set_message(msg.to_string());
				}
			},
			move |content| {
				if !is_ur_line(content) {
					return None;
				}
				let part = content.trim().to_string();
				let mut st = sink_state.lock().expect("UR capture state poisoned");
				if !st.seen.insert(part.clone()) {
					return None;
				}
				let seq = ur_progress(&part);
				if let Some((s, t)) = seq {
					st.total = Some(t);
					st.seqs.insert(s);
				}
				st.parts.push(part);
				let line = match (seq, st.total) {
					(Some((s, _)), Some(t)) => {
						format!("📥 Part {s}/{t} — {}/{t} collected", st.seqs.len())
					},
					_ => format!("📥 UR part captured ({} total)", st.parts.len()),
				};
				progress.println(line);
				progress.set_message(match st.total {
					Some(t) => format!("📷 Collecting signature QR — {}/{t} parts…", st.seqs.len()),
					None => format!("📷 Collecting signature QR — {} parts…", st.parts.len()),
				});
				decode_any_suffix(&st.parts).transpose()
			},
		)
		.await;

		spinner.finish_and_clear();
		let st = state.lock().expect("UR capture state poisoned");
		if result.is_err() && !st.parts.is_empty() {
			match st.total {
				Some(t) => {
					let missing: Vec<String> =
						(1..=t).filter(|s| !st.seqs.contains(s)).map(|s| s.to_string()).collect();
					if missing.is_empty() {
						crate::log_print!(
							"⚠️  All {t} fragments were captured but never formed a consistent payload — was an older signature QR still animating when the scan started?"
						);
					} else {
						crate::log_print!(
							"⚠️  Scan ended with {}/{t} parts — missing: {}",
							st.seqs.len(),
							if missing.len() > 20 {
								format!(
									"{} … ({} more)",
									missing[..20].join(", "),
									missing.len() - 20
								)
							} else {
								missing.join(", ")
							}
						);
					}
				},
				None => crate::log_print!(
					"⚠️  Scan ended with {} parts captured but an incomplete payload",
					st.parts.len()
				),
			}
		}
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

		fn box_blur(luma: &[u8], w: usize, h: usize, radius: usize) -> Vec<u8> {
			let r = radius as i32;
			let mut out = vec![0u8; w * h];
			for y in 0..h as i32 {
				for x in 0..w as i32 {
					let mut sum = 0u32;
					let mut cnt = 0u32;
					for dy in -r..=r {
						for dx in -r..=r {
							let (nx, ny) = (x + dx, y + dy);
							if nx >= 0 && ny >= 0 && nx < w as i32 && ny < h as i32 {
								sum += u32::from(luma[(ny as usize) * w + nx as usize]);
								cnt += 1;
							}
						}
					}
					out[(y as usize) * w + x as usize] = (sum / cnt) as u8;
				}
			}
			out
		}

		/// A fixed-focus Mac camera at phone-scanning distance defocuses the QR
		/// well past what quirc-style decoders tolerate; this blur level is the
		/// regression guard for that (rqrr failed it, rxing decodes it).
		#[test]
		fn decodes_defocused_qr() {
			let data = "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2";
			let (w, h, luma) = render_qr_luma(data, false);
			let blurred = box_blur(&luma, w, h, 5);
			let mut found = Vec::new();
			feed_decoded(&blurred, w, h, |s| {
				found.push(s.to_string());
				None::<()>
			});
			assert!(found.iter().any(|s| s == data), "defocused QR: {found:?}");
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

	/// Untrusted QR/file input may start with multi-byte characters; a byte
	/// slice off a UTF-8 boundary must not panic the scanner.
	#[test]
	fn test_is_ur_line_non_ascii_no_panic() {
		assert!(!is_ur_line("ééééé"));
		assert!(!is_ur_line("🧊🧊"));
		assert!(!is_ur_line("日本語のテキスト"));
	}

	#[test]
	fn test_decode_any_suffix_recovers_from_stale_stream() {
		let old_payload: Vec<u8> = (0..7500u32).map(|i| (i * 31 % 249) as u8).collect();
		let new_payload: Vec<u8> = (0..7500u32).map(|i| (i * 37 % 251) as u8).collect();
		let old_parts = quantus_ur::encode_bytes(&old_payload).unwrap();
		let new_parts = quantus_ur::encode_bytes(&new_payload).unwrap();

		let mut captured = old_parts[..3].to_vec();
		captured.extend(new_parts.iter().cloned());
		assert!(
			!quantus_ur::is_complete(&captured),
			"stale-first capture must wedge the plain decoder for this test to mean anything"
		);
		let bytes = decode_any_suffix(&captured).unwrap().expect("suffix recovery");
		assert_eq!(bytes, new_payload);

		// A COMPLETE stale stream followed by a complete current one: the
		// newest stream must win, not the first complete suffix.
		let mut captured = old_parts.clone();
		captured.extend(new_parts.iter().cloned());
		assert!(quantus_ur::is_complete(&captured[..old_parts.len()]));
		let bytes = decode_any_suffix(&captured).unwrap().expect("both streams complete");
		assert_eq!(bytes, new_payload, "newest complete stream must win over the stale one");
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

	/// Two consecutive exchanges over the same configured path: the first read
	/// consumes the file, and the second must wait for a fresh session instead
	/// of replaying the stale one.
	#[tokio::test]
	async fn test_scan_ur_from_file_consumes_file_between_sessions() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("response.ur");

		let payload_a: Vec<u8> = (0..7219u32).map(|i| (i % 251) as u8).collect();
		let parts_a = quantus_ur::encode_bytes(&payload_a).unwrap();
		std::fs::write(&path, parts_a.join("\n")).unwrap();
		let got = scan_ur(&UrSource::File(path.clone()), Duration::from_secs(5)).await.unwrap();
		assert_eq!(got, payload_a);
		assert!(!path.exists(), "file must be consumed after a successful read");

		let payload_b: Vec<u8> = (0..7219u32).map(|i| ((i * 3) % 251) as u8).collect();
		let parts_b = quantus_ur::encode_bytes(&payload_b).unwrap();
		let writer = {
			let path = path.clone();
			tokio::spawn(async move {
				tokio::time::sleep(Duration::from_millis(300)).await;
				std::fs::write(&path, parts_b.join("\n")).unwrap();
			})
		};
		let got = scan_ur(&UrSource::File(path.clone()), Duration::from_secs(5)).await.unwrap();
		assert_eq!(got, payload_b, "second exchange must return the fresh session");
		writer.await.unwrap();
		assert!(!path.exists());
	}

	#[tokio::test]
	async fn test_scan_ur_from_file_times_out() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("never-written.ur");
		let result = scan_ur(&UrSource::File(path), Duration::from_millis(100)).await;
		assert!(result.is_err());
	}
}
