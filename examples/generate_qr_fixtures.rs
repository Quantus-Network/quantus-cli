//! Generates the cold-signing QR fixture corpus used to test wallet parsing.
//!
//! Each fixture is a complete signing payload (call + signed extensions) wrapped in the
//! `{"v":1,"signer":...,"payload":"0x.."}` envelope and UR-encoded into QR frames, which is
//! exactly what a cold wallet scans. Every consumer of the corpus — the Keystone firmware
//! parser, the cold wallet app, the reference parser — reads the same bytes.
//!
//! Run: cargo run --example generate_qr_fixtures -- <output-dir>

use codec::{Compact, Encode};
use qrcode::{types::Color, EcLevel, QrCode};
use quantus_cli::chain::quantus_subxt::api;
use std::{fs, path::Path};

/// Planck, so the firmware's `KNOWN_NETWORKS` check accepts these payloads.
const PLANCK_GENESIS: [u8; 32] = [
	0x49, 0x01, 0xbf, 0x5c, 0x57, 0xfd, 0x3f, 0x9e, 0x72, 0x6a, 0xf3, 0x99, 0xc7, 0x63, 0xde, 0x66,
	0x70, 0xdb, 0xdb, 0x11, 0x5a, 0x91, 0xc0, 0x23, 0x7e, 0x17, 0x3f, 0x16, 0xee, 0xf6, 0x5e, 0x72,
];
const SPEC_VERSION: u32 = 147;
const TRANSACTION_VERSION: u32 = 6;

/// The signer the request is addressed to. Any valid Quantus address works; the wallet only
/// signs when it holds this account.
const SIGNER_SS58: &str = "qzn9sph6ZoQxwseSFyrdfTUEWmozsex7hhCJQPG29nbgesGei";

const DEST: [u8; 32] = [0x77; 32];
const MULTISIG: [u8; 32] = [0x99; 32];
const SIGNER_A: [u8; 32] = [0xaa; 32];
const SIGNER_B: [u8; 32] = [0xbb; 32];
const SIGNER_C: [u8; 32] = [0xcc; 32];

const UNIT: u128 = 1_000_000_000_000;

struct Fixture {
	slug: &'static str,
	pallet_call: &'static str,
	/// The call a wallet must show nested inside this one, if any.
	inner_call: Option<&'static str>,
	description: &'static str,
	call: Vec<u8>,
}

fn dest(
) -> subxt::ext::subxt_core::utils::MultiAddress<subxt::ext::subxt_core::utils::AccountId32, ()> {
	subxt::ext::subxt_core::utils::MultiAddress::Id(subxt::ext::subxt_core::utils::AccountId32(
		DEST,
	))
}

fn account(bytes: [u8; 32]) -> subxt::ext::subxt_core::utils::AccountId32 {
	subxt::ext::subxt_core::utils::AccountId32(bytes)
}

/// Call bytes, encoded through the same metadata the CLI signs with.
fn call_data<C: subxt::tx::Payload>(metadata: &subxt::Metadata, call: &C) -> Vec<u8> {
	call.encode_call_data(metadata)
		.expect("call encodes against the bundled metadata")
}

fn transfer_call(metadata: &subxt::Metadata, amount: u128) -> Vec<u8> {
	call_data(metadata, &api::tx().balances().transfer_allow_death(dest(), amount))
}

/// The `TxExtension` bytes that follow the call: explicit parts, then the implicit ones.
fn extension_suffix(nonce: u32, tip: u128) -> Vec<u8> {
	let mut v = Vec::new();
	v.push(0); // era: immortal
	v.extend(Compact(nonce).encode());
	v.extend(Compact(tip).encode());
	v.push(0); // CheckMetadataHash mode: disabled
	v.extend_from_slice(&SPEC_VERSION.to_le_bytes());
	v.extend_from_slice(&TRANSACTION_VERSION.to_le_bytes());
	v.extend_from_slice(&PLANCK_GENESIS);
	v.extend_from_slice(&[0x11; 32]); // block hash, immortal so not checked
	v.push(0); // metadata hash: None
	v
}

fn signing_payload(call: &[u8], nonce: u32, tip: u128) -> Vec<u8> {
	let mut payload = call.to_vec();
	payload.extend(extension_suffix(nonce, tip));
	payload
}

fn envelope(payload: &[u8]) -> String {
	format!(r#"{{"v":1,"signer":"{}","payload":"0x{}"}}"#, SIGNER_SS58, hex::encode(payload))
}

/// A QR frame as standalone SVG, so the corpus needs no image toolchain and works offline.
///
/// One module per unit with a viewBox, and horizontal runs merged into a single path, which
/// keeps a frame around 5 KB instead of 100 KB of individual rects.
fn frame_svg(part: &str) -> String {
	const QUIET: usize = 4;
	let code = QrCode::with_error_correction_level(part.as_bytes(), EcLevel::L)
		.expect("UR part fits in a QR code");
	let width = code.width();
	let modules = code.to_colors();
	let size = width + QUIET * 2;

	let mut path = String::new();
	for y in 0..width {
		let mut x = 0;
		while x < width {
			if modules[y * width + x] != Color::Dark {
				x += 1;
				continue;
			}
			let start = x;
			while x < width && modules[y * width + x] == Color::Dark {
				x += 1;
			}
			let run = x - start;
			path.push_str(&format!("M{} {}h{run}v1h-{run}z", start + QUIET, y + QUIET));
		}
	}

	format!(
		r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{px}" height="{px}" shape-rendering="crispEdges"><rect width="{size}" height="{size}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##,
		px = size * 8
	)
}

/// A page that cycles the frames, for holding up to the simulator or a device camera.
fn viewer_html(slug: &str, description: &str, frames: usize) -> String {
	format!(
		r#"<!doctype html>
<meta charset="utf-8">
<title>{slug}</title>
<style>
  body {{ margin: 0; display: grid; place-items: center; min-height: 100vh;
         font: 14px system-ui, sans-serif; background: #fff; color: #111; }}
  img {{ width: 420px; image-rendering: pixelated; }}
  p {{ margin: 8px 0 0; }}
</style>
<img id="f">
<p>{description}</p>
<p><b>{slug}</b> — frame <span id="n">1</span>/{frames} — <span id="ms">200</span>ms
   (&larr;/&rarr; to change speed)</p>
<script>
  const total = {frames};
  let i = 0, ms = 200;
  const img = document.getElementById('f'), n = document.getElementById('n');
  const msEl = document.getElementById('ms');
  const pad = v => String(v).padStart(3, '0');
  let timer;
  function tick() {{
    img.src = `frames/frame-${{pad(i)}}.svg`;
    n.textContent = i + 1;
    i = (i + 1) % total;
  }}
  function restart() {{ clearInterval(timer); timer = setInterval(tick, ms); msEl.textContent = ms; }}
  addEventListener('keydown', e => {{
    if (e.key === 'ArrowLeft') ms = Math.min(2000, ms + 50);
    if (e.key === 'ArrowRight') ms = Math.max(50, ms - 50);
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') restart();
  }});
  tick(); restart();
</script>
"#
	)
}

/// Landing page listing every case, so a tester can pick one and show it to a camera.
fn index_html(links: &[String]) -> String {
	format!(
		r#"<!doctype html>
<meta charset="utf-8">
<title>Cold signing QR fixtures</title>
<style>
  body {{ font: 15px system-ui, sans-serif; margin: 40px auto; max-width: 640px; color: #111; }}
  li {{ margin: 6px 0; }}
  span {{ color: #666; font-size: 13px; }}
</style>
<h1>Cold signing QR fixtures</h1>
<p>Reduced set: the calls the Keystone firmware parses today. Open one, then point the
   device or simulator at the animated QR.</p>
<ul>
{}
</ul>
"#,
		links.join("\n")
	)
}

fn build_fixtures(metadata: &subxt::Metadata) -> Vec<Fixture> {
	let inner_transfer = transfer_call(metadata, 42 * UNIT);

	let reversible_with_delay = call_data(
		metadata,
		&api::tx().reversible_transfers().schedule_transfer_with_delay(
			dest(),
			5 * UNIT,
			api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::Timestamp(3_600_000),
		),
	);

	vec![
		Fixture {
			slug: "01-transfer-allow-death",
			inner_call: None,
			pallet_call: "balances.transfer_allow_death",
			description: "Plain transfer of 1 QUAN.",
			call: transfer_call(metadata, UNIT),
		},
		Fixture {
			slug: "02-transfer-keep-alive",
			inner_call: None,
			pallet_call: "balances.transfer_keep_alive",
			description: "Transfer of 2.5 QUAN that leaves the account above existential deposit.",
			call: call_data(
				metadata,
				&api::tx().balances().transfer_keep_alive(dest(), 2_500_000_000_000u128),
			),
		},
		Fixture {
			slug: "03-schedule-transfer",
			inner_call: None,
			pallet_call: "reversible_transfers.schedule_transfer",
			description: "Reversible transfer of 3 QUAN using the account's configured delay.",
			call: call_data(
				metadata,
				&api::tx().reversible_transfers().schedule_transfer(dest(), 3 * UNIT),
			),
		},
		Fixture {
			slug: "04-schedule-transfer-with-delay",
			inner_call: None,
			pallet_call: "reversible_transfers.schedule_transfer_with_delay",
			description: "Reversible transfer of 5 QUAN with an explicit one-hour reversal window.",
			call: reversible_with_delay,
		},
		Fixture {
			slug: "05-multisig-create",
			inner_call: None,
			pallet_call: "multisig.create_multisig",
			description: "Create a 2-of-3 multisig.",
			call: call_data(
				metadata,
				&api::tx().multisig().create_multisig(
					vec![account(SIGNER_A), account(SIGNER_B), account(SIGNER_C)],
					2,
					0,
				),
			),
		},
		Fixture {
			slug: "06-multisig-propose-transfer",
			inner_call: Some("balances.transfer_allow_death"),
			pallet_call: "multisig.propose",
			description: "Propose a 42 QUAN transfer from the multisig.",
			call: call_data(
				metadata,
				&api::tx().multisig().propose(
					account(MULTISIG),
					api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
						inner_transfer.clone(),
					),
					5_000_000,
				),
			),
		},
		Fixture {
			slug: "07-multisig-approve-transfer",
			inner_call: Some("balances.transfer_allow_death"),
			pallet_call: "multisig.approve",
			description: "Approve proposal 7, which carries the 42 QUAN transfer being approved.",
			call: call_data(
				metadata,
				&api::tx().multisig().approve(
					account(MULTISIG),
					7,
					api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
						inner_transfer.clone(),
					),
				),
			),
		},
		Fixture {
			slug: "08-multisig-execute-transfer",
			inner_call: Some("balances.transfer_allow_death"),
			pallet_call: "multisig.execute",
			description: "Execute proposal 7, which carries the 42 QUAN transfer being dispatched.",
			call: call_data(
				metadata,
				&api::tx().multisig().execute(
					account(MULTISIG),
					7,
					api::runtime_types::quantus_runtime::RuntimeCall::Balances(
						api::runtime_types::pallet_balances::pallet::Call::transfer_allow_death {
							dest: dest(),
							value: 42 * UNIT,
						},
					),
				),
			),
		},
		Fixture {
			slug: "09-multisig-execute-reversible",
			inner_call: Some("reversible_transfers.schedule_transfer"),
			pallet_call: "multisig.execute",
			description:
				"Execute a proposal whose inner call is a reversible transfer, not a plain one.",
			call: call_data(
				metadata,
				&api::tx().multisig().execute(
					account(MULTISIG),
					8,
					api::runtime_types::quantus_runtime::RuntimeCall::ReversibleTransfers(
						api::runtime_types::pallet_reversible_transfers::pallet::Call::schedule_transfer {
							dest: dest(),
							amount: 5 * UNIT,
						},
					),
				),
			),
		},
	]
}

fn main() {
	let out_dir = std::env::args()
		.nth(1)
		.unwrap_or_else(|| panic!("usage: generate_qr_fixtures <output-dir>"));
	let root = Path::new(&out_dir);

	let metadata_bytes: &[u8] = include_bytes!("../src/quantus_metadata.scale");
	let metadata = <subxt::Metadata as codec::Decode>::decode(&mut &metadata_bytes[..])
		.expect("bundled metadata decodes");

	let reduced = root.join("reduced");
	fs::create_dir_all(&reduced).expect("create fixture dir");

	let mut manifest = Vec::new();
	let mut links = Vec::new();
	for fixture in build_fixtures(&metadata) {
		let payload = signing_payload(&fixture.call, 0, 0);
		let request = envelope(&payload);
		let parts = quantus_ur::encode_bytes(request.as_bytes()).expect("UR encodes");

		let dir = reduced.join(fixture.slug);
		let frames_dir = dir.join("frames");
		fs::create_dir_all(&frames_dir).expect("create case dir");

		for (i, part) in parts.iter().enumerate() {
			fs::write(frames_dir.join(format!("frame-{i:03}.svg")), frame_svg(part))
				.expect("write frame");
		}
		fs::write(dir.join("ur.txt"), format!("{}\n", parts.join("\n"))).expect("write ur");
		fs::write(dir.join("payload.hex"), format!("0x{}\n", hex::encode(&payload)))
			.expect("write payload");
		fs::write(dir.join("request.json"), format!("{request}\n")).expect("write request");
		fs::write(
			dir.join("index.html"),
			viewer_html(fixture.slug, fixture.description, parts.len()),
		)
		.expect("write viewer");

		println!(
			"{:<34} call {:>5}B  payload {:>5}B  {:>3} frames",
			fixture.slug,
			fixture.call.len(),
			payload.len(),
			parts.len()
		);

		links.push(format!(
			r#"<li><a href="{}/index.html">{}</a> <span>{} &middot; {} frames</span></li>"#,
			fixture.slug,
			fixture.slug,
			fixture.pallet_call,
			parts.len()
		));

		manifest.push(format!(
			r#"    {{
      "slug": "{}",
      "call": "{}",
      "description": "{}",
      "innerCall": {},
      "signer": "{}",
      "callBytes": {},
      "payloadBytes": {},
      "frames": {}
    }}"#,
			fixture.slug,
			fixture.pallet_call,
			fixture.description,
			fixture
				.inner_call
				.map(|c| format!("\"{c}\""))
				.unwrap_or_else(|| "null".to_string()),
			SIGNER_SS58,
			fixture.call.len(),
			payload.len(),
			parts.len()
		));
	}

	let manifest = format!(
		"{{\n  \"specVersion\": {SPEC_VERSION},\n  \"transactionVersion\": {TRANSACTION_VERSION},\n  \"network\": \"Planck\",\n  \"cases\": [\n{}\n  ]\n}}\n",
		manifest.join(",\n")
	);
	fs::write(reduced.join("manifest.json"), manifest).expect("write manifest");
	fs::write(reduced.join("index.html"), index_html(&links)).expect("write index");
	println!("\nwrote fixtures to {}", reduced.display());
}
