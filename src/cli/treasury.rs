//! `quantus treasury` subcommand - manage Treasury
use crate::{chain::quantus_subxt, cli::common::submit_transaction, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;

/// Treasury management commands
#[derive(Subcommand, Debug)]
pub enum TreasuryCommands {
	/// Check current Treasury balance
	Balance,

	/// Get Treasury configuration
	Config,

	/// Show Treasury information and how to spend from it
	Info,

	/// Submit a Treasury spend proposal via referendum (requires specific track)
	/// This creates a referendum that, if approved, will approve a treasury spend
	SubmitSpend {
		/// Beneficiary address (will receive the funds)
		#[arg(long)]
		beneficiary: String,

		/// Amount to spend (e.g., "100.0" for 100 QUAN)
		#[arg(long)]
		amount: String,

		/// Track to use: "small", "medium", "big", or "treasurer"
		/// - small: < 100 QUAN (Track 2)
		/// - medium: < 1000 QUAN (Track 3)
		/// - big: < 10000 QUAN (Track 4)
		/// - treasurer: any amount (Track 5)
		#[arg(long)]
		track: String,

		/// Wallet name to sign the transaction
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Payout an approved Treasury spend (anyone can call this)
	Payout {
		/// Spend index to payout
		#[arg(long)]
		index: u32,

		/// Wallet name to sign the transaction
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Check and cleanup a Treasury spend status
	CheckStatus {
		/// Spend index to check
		#[arg(long)]
		index: u32,

		/// Wallet name to sign the transaction
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// List active Treasury spends
	ListSpends,

	/// Directly create a Treasury spend via sudo (root only, for testing)
	SpendSudo {
		/// Beneficiary address (will receive the funds)
		#[arg(long)]
		beneficiary: String,

		/// Amount to spend (e.g., "50.0" for 50 QUAN)
		#[arg(long)]
		amount: String,

		/// Wallet name to sign with (must have sudo)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Handle treasury commands
pub async fn handle_treasury_command(
	command: TreasuryCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TreasuryCommands::Balance => get_treasury_balance(&quantus_client).await,
		TreasuryCommands::Config => get_config(&quantus_client).await,
		TreasuryCommands::Info => show_treasury_info().await,
		TreasuryCommands::SubmitSpend {
			beneficiary,
			amount,
			track,
			from,
			password,
			password_file,
		} =>
			submit_spend_referendum(
				&quantus_client,
				&beneficiary,
				&amount,
				&track,
				&from,
				password,
				password_file,
			)
			.await,
		TreasuryCommands::Payout { index, from, password, password_file } =>
			payout_spend(&quantus_client, index, &from, password, password_file).await,
		TreasuryCommands::CheckStatus { index, from, password, password_file } =>
			check_spend_status(&quantus_client, index, &from, password, password_file).await,
		TreasuryCommands::ListSpends => list_spends(&quantus_client).await,
		TreasuryCommands::SpendSudo { beneficiary, amount, from, password, password_file } =>
			spend_sudo(&quantus_client, &beneficiary, &amount, &from, password, password_file).await,
	}
}

/// Get current Treasury balance
async fn get_treasury_balance(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("💰 Treasury Balance");
	log_print!("");

	// Get Treasury account ID
	// PalletId("py/trsry") converts to account using "modl" prefix
	let mut full_data = [0u8; 32];
	full_data[0..4].copy_from_slice(b"modl");
	full_data[4..12].copy_from_slice(b"py/trsry");
	let treasury_account = subxt::utils::AccountId32(full_data);

	// Query balance
	let addr = quantus_subxt::api::storage().system().account(treasury_account.clone());

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let account_info = storage_at.fetch(&addr).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic("Treasury account not found".to_string())
	})?;

	let free_balance = account_info.data.free;
	let reserved_balance = account_info.data.reserved;

	let formatted_free_balance =
		crate::cli::send::format_balance_with_symbol(quantus_client, free_balance).await?;
	let formatted_reserved_balance =
		crate::cli::send::format_balance_with_symbol(quantus_client, reserved_balance).await?;

	log_print!("💰 Free Balance: {}", formatted_free_balance);
	log_print!("💰 Reserved: {}", formatted_reserved_balance);
	log_print!("📍 Treasury Account: {}", treasury_account.to_string().bright_yellow());

	Ok(())
}

/// Get Treasury configuration
async fn get_config(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("⚙️  Treasury Configuration");
	log_print!("");

	let constants = quantus_client.client().constants();

	// Get SpendPeriod
	if let Ok(spend_period) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().spend_period())
	{
		log_print!("⏰ Spend Period: {} blocks", spend_period.to_string().bright_cyan());
		let hours = spend_period as f64 * 3.0 / 3600.0; // Assuming 3 sec blocks
		log_print!("   (~{:.1} hours)", hours);
	}

	// Get Burn percentage
	if let Ok(burn) = constants.at(&quantus_subxt::api::constants().treasury_pallet().burn()) {
		log_print!("🔥 Burn: {:?}", burn);
	}

	// Get MaxApprovals
	if let Ok(max_approvals) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().max_approvals())
	{
		log_print!("📊 Max Approvals: {}", max_approvals.to_string().bright_yellow());
	}

	// Get PayoutPeriod
	if let Ok(payout_period) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().payout_period())
	{
		log_print!("💸 Payout Period: {} blocks", payout_period.to_string().bright_green());
		let days = payout_period as f64 * 3.0 / 86400.0; // Assuming 3 sec blocks
		log_print!("   (~{:.1} days)", days);
	}

	Ok(())
}

/// Show Treasury information
async fn show_treasury_info() -> crate::error::Result<()> {
	log_print!("💰 Treasury Information");
	log_print!("");
	log_print!("The Treasury is a pot of funds collected through:");
	log_print!("   • Transaction fees");
	log_print!("   • Slashing");
	log_print!("   • Other network mechanisms");
	log_print!("");
	log_print!("📋 {} To spend from Treasury:", "HOW TO USE".bright_cyan().bold());
	log_print!("");
	log_print!(
		"1. {} Create a spending proposal using Referenda:",
		"Treasury Tracks".bright_yellow().bold()
	);
	log_print!("   • Track 2: Treasury Small Spender (< certain amount)");
	log_print!("   • Track 3: Treasury Medium Spender");
	log_print!("   • Track 4: Treasury Big Spender");
	log_print!("   • Track 5: Treasury Treasurer (highest amounts)");
	log_print!("");
	log_print!(
		"2. {} Submit referendum with Treasury spend call:",
		"Example".bright_green().bold()
	);
	log_print!(
		"   quantus referenda submit-remark --message \"Treasury spend: 1000 QUAN to Alice\""
	);
	log_print!("   --from <YOUR_WALLET> --password <PASSWORD>");
	log_print!("");
	log_print!("   Note: Use appropriate origin for treasury tracks");
	log_print!("");
	log_print!("3. {} Community votes on the proposal", "Voting".bright_magenta().bold());
	log_print!("");
	log_print!("4. {} If approved, funds are paid automatically", "Execution".bright_blue().bold());
	log_print!("");
	log_print!("💡 {}", "Useful Commands:".bright_cyan().bold());
	log_print!("   quantus treasury balance     - Check Treasury balance");
	log_print!("   quantus treasury config      - View Treasury configuration");
	log_print!("   quantus referenda config     - View available tracks");
	log_print!("");

	Ok(())
}

/// Submit a Treasury spend proposal via referendum
async fn submit_spend_referendum(
	quantus_client: &crate::chain::client::QuantusClient,
	beneficiary: &str,
	amount: &str,
	track: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	use qp_poseidon::PoseidonHasher;
	use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
	use subxt::tx::Payload;

	log_print!("💰 Submitting Treasury Spend Referendum");
	log_print!("   📍 Beneficiary: {}", beneficiary.bright_yellow());
	log_print!("   💵 Amount: {}", amount.bright_green());
	log_print!("   🛤️  Track: {}", track.bright_cyan());

	// Parse amount
	let amount_value = crate::cli::send::parse_amount(quantus_client, amount).await?;

	// Parse beneficiary address
	let beneficiary_resolved = crate::cli::common::resolve_address(beneficiary)?;
	let (beneficiary_sp, _) = SpAccountId32::from_ss58check_with_version(&beneficiary_resolved)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Invalid beneficiary address '{beneficiary}': {e:?}"
			))
		})?;
	let bytes: [u8; 32] = *beneficiary_sp.as_ref();
	let beneficiary_account = subxt::utils::AccountId32::from(bytes);

	// Create the treasury spend call using the transaction API
	let beneficiary_multi = subxt::utils::MultiAddress::Id(beneficiary_account.clone());

	let treasury_spend_call =
		quantus_subxt::api::tx()
			.treasury_pallet()
			.spend((), amount_value, beneficiary_multi, None);

	// Encode call_data
	let encoded_call = treasury_spend_call
		.encode_call_data(&quantus_client.client().metadata())
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to encode call: {:?}", e))
		})?;

	log_print!("📝 Creating preimage...");

	// Load wallet keypair
	let keypair =
		crate::wallet::load_keypair_from_wallet(from, password.clone(), password_file.clone())?;

	// Calculate preimage hash using Poseidon (runtime uses PoseidonHasher)
	let preimage_hash: sp_core::H256 =
		<PoseidonHasher as sp_runtime::traits::Hash>::hash(&encoded_call);

	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	// Submit preimage
	let preimage_call = quantus_subxt::api::tx().preimage().note_preimage(encoded_call.clone());
	let preimage_tx_hash =
		submit_transaction(quantus_client, &keypair, preimage_call, None, false).await?;

	log_print!("✅ Preimage created {:?}", preimage_tx_hash);

	// Determine the origin based on track
	let origin_caller = match track.to_lowercase().as_str() {
		"small" => quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::Origins(
			quantus_subxt::api::runtime_types::quantus_runtime::governance::origins::pallet_custom_origins::Origin::SmallSpender,
		),
		"medium" => quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::Origins(
			quantus_subxt::api::runtime_types::quantus_runtime::governance::origins::pallet_custom_origins::Origin::MediumSpender,
		),
		"big" => quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::Origins(
			quantus_subxt::api::runtime_types::quantus_runtime::governance::origins::pallet_custom_origins::Origin::BigSpender,
		),
		"treasurer" => quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::Origins(
			quantus_subxt::api::runtime_types::quantus_runtime::governance::origins::pallet_custom_origins::Origin::Treasurer,
		),
		_ => {
			return Err(crate::error::QuantusError::Generic(format!(
				"Invalid track: {}. Must be 'small', 'medium', 'big', or 'treasurer'",
				track
			)))
		},
	};

	// Create the bounded proposal
	let proposal =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded::Lookup {
			hash: preimage_hash,
			len: encoded_call.len() as u32,
		};

	log_print!("📜 Submitting referendum...");

	// Submit referendum with DispatchTime::After
	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			1u32,
		);
	let submit_call =
		quantus_subxt::api::tx().referenda().submit(origin_caller, proposal, enactment);
	let submit_tx_hash =
		submit_transaction(quantus_client, &keypair, submit_call, None, false).await?;

	log_print!(
		"✅ {} Treasury spend referendum submitted! {:?}",
		"SUCCESS".bright_green().bold(),
		submit_tx_hash
	);
	log_print!("💡 Next steps:");
	log_print!("   1. Place decision deposit: quantus referenda place-decision-deposit --index <INDEX> --from {}", from);
	log_print!(
		"   2. Vote on the referendum: quantus referenda vote --index <INDEX> --aye --from <VOTER>"
	);
	log_print!(
		"   3. After approval, payout: quantus treasury payout --index <SPEND_INDEX> --from {}",
		from
	);

	Ok(())
}

/// Payout an approved Treasury spend
async fn payout_spend(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	log_print!("💸 Paying out Treasury Spend #{}", index);

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create payout call
	let payout_call = quantus_subxt::api::tx().treasury_pallet().payout(index);

	let tx_hash = submit_transaction(quantus_client, &keypair, payout_call, None, false).await?;
	log_print!(
		"✅ {} Payout transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Treasury spend paid out!", "FINISHED".bright_green().bold());
	log_print!("💡 Use 'quantus treasury check-status --index {}' to cleanup", index);

	Ok(())
}

/// Check and cleanup a Treasury spend status
async fn check_spend_status(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	log_print!("🔍 Checking Treasury Spend #{} status", index);

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create check_status call
	let check_call = quantus_subxt::api::tx().treasury_pallet().check_status(index);

	let tx_hash = submit_transaction(quantus_client, &keypair, check_call, None, false).await?;
	log_print!(
		"✅ {} Check status transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Spend status checked and cleaned up!", "FINISHED".bright_green().bold());

	Ok(())
}

/// List active Treasury spends
async fn list_spends(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("📋 Active Treasury Spends");
	log_print!("");

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Iterate through spend storage indices (0 to 100 for example)
	let mut count = 0;
	for spend_index in 0..100 {
		let spend_addr = quantus_subxt::api::storage().treasury_pallet().spends(spend_index);
		if let Some(spend_status) = storage_at.fetch(&spend_addr).await? {
			log_print!("💰 Spend #{}", spend_index.to_string().bright_yellow().bold());
			log_print!("   Amount: {} (raw)", spend_status.amount.to_string().bright_green());
			log_print!(
				"   Beneficiary: {}",
				format!("{:?}", spend_status.beneficiary).bright_cyan()
			);
			log_print!("   Valid From: Block #{}", spend_status.valid_from);
			log_print!("   Expires At: Block #{}", spend_status.expire_at);
			log_print!(
				"   Status: {}",
				match spend_status.status {
					quantus_subxt::api::runtime_types::pallet_treasury::PaymentState::Pending =>
						"Pending".bright_yellow(),
					quantus_subxt::api::runtime_types::pallet_treasury::PaymentState::Attempted { .. } =>
						"Attempted".bright_blue(),
					quantus_subxt::api::runtime_types::pallet_treasury::PaymentState::Failed =>
						"Failed".bright_red(),
				}
			);
			log_print!("");
			count += 1;
		}
	}

	if count == 0 {
		log_print!("📭 No active Treasury spends found");
	} else {
		log_print!("Total: {} active spend(s)", count.to_string().bright_green().bold());
	}

	Ok(())
}

/// Directly create a Treasury spend via sudo (testing/root only)
async fn spend_sudo(
	quantus_client: &crate::chain::client::QuantusClient,
	beneficiary: &str,
	amount: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

	log_print!("💰 Creating Treasury Spend via Sudo (Root)");
	log_print!("   📍 Beneficiary: {}", beneficiary.bright_yellow());
	log_print!("   💵 Amount: {}", amount.bright_green());
	log_print!("   ⚠️  Using ROOT permissions (sudo)");

	// Parse amount
	let amount_value = crate::cli::send::parse_amount(quantus_client, amount).await?;

	// Parse beneficiary address
	let beneficiary_resolved = crate::cli::common::resolve_address(beneficiary)?;
	let (beneficiary_sp, _) = SpAccountId32::from_ss58check_with_version(&beneficiary_resolved)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Invalid beneficiary address '{beneficiary}': {e:?}"
			))
		})?;
	let bytes: [u8; 32] = *beneficiary_sp.as_ref();
	let beneficiary_account = subxt::utils::AccountId32::from(bytes);
	let beneficiary_multi = subxt::utils::MultiAddress::Id(beneficiary_account.clone());

	// Create the treasury spend call
	let spend_call = quantus_subxt::api::Call::TreasuryPallet(
		quantus_subxt::api::treasury_pallet::Call::spend {
			asset_kind: Box::new(()),
			amount: amount_value,
			beneficiary: Box::new(beneficiary_multi),
			valid_from: None,
		},
	);

	// Wrap with sudo
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(spend_call);

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Submit transaction
	log_print!("📡 Submitting sudo transaction...");
	let tx_hash = submit_transaction(quantus_client, &keypair, sudo_call, None, false).await?;
	log_print!(
		"✅ {} Sudo transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Treasury spend created via sudo!", "FINISHED".bright_green().bold());
	log_print!("💡 Next step: quantus treasury list-spends");
	log_print!("💡 Then payout: quantus treasury payout --index <INDEX> --from {}", beneficiary);

	Ok(())
}
