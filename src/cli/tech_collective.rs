//! `quantus tech-collective` subcommand - tech collective management
use crate::{
	chain::quantus_subxt,
	cli::{address_format::QuantusSS58, common::resolve_address},
	error::QuantusError,
	log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};

/// Tech Collective management commands
#[derive(Subcommand, Debug)]
pub enum TechCollectiveCommands {
	/// Add a member to the Tech Collective
	AddMember {
		/// Address of the member to add
		#[arg(short, long)]
		who: String,

		/// Wallet name to sign with (must have root or collective permissions)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Remove a member from the Tech Collective
	RemoveMember {
		/// Address of the member to remove
		#[arg(short, long)]
		who: String,

		/// Wallet name to sign with (must have root permissions)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Vote on a Tech Referenda proposal
	Vote {
		/// Referendum index to vote on
		#[arg(short, long)]
		referendum_index: u32,

		/// Vote (true for aye, false for nay)
		#[arg(short, long)]
		aye: bool,

		/// Wallet name to sign with (must be a collective member)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// List all Tech Collective members
	ListMembers,

	/// Check if an address is a member of the Tech Collective
	IsMember {
		/// Address to check
		#[arg(short, long)]
		address: String,
	},

	/// Check who has sudo permissions in the network
	CheckSudo {
		/// Address to check if it's the sudo account (optional)
		#[arg(short, long)]
		address: Option<String>,
	},

	/// List active Tech Referenda
	ListReferenda,

	/// Get details of a specific Tech Referendum
	GetReferendum {
		/// Referendum index
		#[arg(short, long)]
		index: u32,
	},
}

/// Add a member to the Tech Collective using sudo
pub async fn add_member(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	who_address: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("🏛️  Adding member to Tech Collective...");
	log_verbose!("   Member: {}", who_address.bright_cyan());

	// Parse the member address
	let (member_account_sp, _) = AccountId32::from_ss58check_with_version(who_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid member address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let member_account_bytes: [u8; 32] = *member_account_sp.as_ref();
	let member_account_id = subxt::ext::subxt_core::utils::AccountId32::from(member_account_bytes);

	log_verbose!("✍️  Creating add_member transaction...");

	// Create the TechCollective::add_member call as RuntimeCall enum
	let add_member_call = quantus_subxt::api::Call::TechCollective(
		quantus_subxt::api::tech_collective::Call::add_member {
			who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id),
		},
	);

	// Wrap in Sudo::sudo call
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(add_member_call);

	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		sudo_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Add member transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Remove a member from the Tech Collective using sudo
pub async fn remove_member(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	who_address: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("🏛️  Removing member from Tech Collective...");
	log_verbose!("   Member: {}", who_address.bright_cyan());

	// Parse the member address
	let (member_account_sp, _) = AccountId32::from_ss58check_with_version(who_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid member address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let member_account_bytes: [u8; 32] = *member_account_sp.as_ref();
	let member_account_id = subxt::ext::subxt_core::utils::AccountId32::from(member_account_bytes);

	log_verbose!("✍️  Creating remove_member transaction...");

	// Create the TechCollective::remove_member call as RuntimeCall enum
	let remove_member_call = quantus_subxt::api::Call::TechCollective(
		quantus_subxt::api::tech_collective::Call::remove_member {
			who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id),
			min_rank: 0u16, // Use rank 0 as default
		},
	);

	// Wrap in Sudo::sudo call
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(remove_member_call);

	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		sudo_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Remove member transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Vote on a Tech Referenda proposal
pub async fn vote_on_referendum(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	referendum_index: u32,
	aye: bool,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("🗳️  Voting on referendum...");
	log_verbose!("   Referendum: {}", referendum_index);
	log_verbose!("   Vote: {}", if aye { "AYE" } else { "NAY" });

	log_verbose!("✍️  Creating vote transaction...");

	// Create the TechCollective::vote call
	let vote_call = quantus_subxt::api::tx().tech_collective().vote(referendum_index, aye);

	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		vote_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Vote transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Check if an address is a member of the Tech Collective
pub async fn is_member(
	quantus_client: &crate::chain::client::QuantusClient,
	address: &str,
) -> crate::error::Result<bool> {
	log_verbose!("🔍 Checking membership...");
	log_verbose!("   Address: {}", address.bright_cyan());

	// Parse the address
	let (account_sp, _) = AccountId32::from_ss58check_with_version(address)
		.map_err(|e| QuantusError::Generic(format!("Invalid address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let account_bytes: [u8; 32] = *account_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

	// Query Members storage
	let storage_addr = quantus_subxt::api::storage().tech_collective().members(account_id);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let member_data = storage_at
		.fetch(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to fetch member data: {e:?}")))?;

	Ok(member_data.is_some())
}

/// Get member count information
pub async fn get_member_count(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<Option<u32>> {
	log_verbose!("🔍 Getting member count...");

	// Query MemberCount storage - use rank 0 as default
	let storage_addr = quantus_subxt::api::storage().tech_collective().member_count(0u16);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let count_data = storage_at
		.fetch(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to fetch member count: {e:?}")))?;

	Ok(count_data)
}

/// Get list of all members
pub async fn get_member_list(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<Vec<AccountId32>> {
	log_verbose!("🔍 Getting member list...");

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Query all Members storage entries
	let members_storage = quantus_subxt::api::storage().tech_collective().members_iter();

	let mut members = Vec::new();
	let mut iter = storage_at.iter(members_storage).await.map_err(|e| {
		QuantusError::NetworkError(format!("Failed to create members iterator: {e:?}"))
	})?;

	while let Some(result) = iter.next().await {
		match result {
			Ok(storage_entry) => {
				let key = storage_entry.key_bytes;
				// The key contains the AccountId32 after the storage prefix
				// TechCollective Members storage key format: prefix + AccountId32
				if key.len() >= 32 {
					// Extract the last 32 bytes as AccountId32
					let account_bytes: [u8; 32] =
						key[key.len() - 32..].try_into().unwrap_or([0u8; 32]);
					let sp_account = AccountId32::from(account_bytes);
					log_verbose!("Found member: {}", sp_account.to_quantus_ss58());
					members.push(sp_account);
				}
			},
			Err(e) => {
				log_verbose!("⚠️  Error reading member entry: {:?}", e);
			},
		}
	}

	log_verbose!("Found {} total members", members.len());
	Ok(members)
}

/// Get sudo account information
pub async fn get_sudo_account(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<Option<AccountId32>> {
	log_verbose!("🔍 Getting sudo account...");

	// Query Sudo::Key storage
	let storage_addr = quantus_subxt::api::storage().sudo().key();

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let sudo_account = storage_at
		.fetch(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to fetch sudo account: {e:?}")))?;

	// Convert from subxt_core AccountId32 to sp_core AccountId32
	if let Some(subxt_account) = sudo_account {
		let account_bytes: [u8; 32] = *subxt_account.as_ref();
		let sp_account = AccountId32::from(account_bytes);
		Ok(Some(sp_account))
	} else {
		Ok(None)
	}
}

/// Handle tech collective subxt commands
pub async fn handle_tech_collective_command(
	command: TechCollectiveCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🏛️  Tech Collective");

	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TechCollectiveCommands::AddMember { who, from, password, password_file } => {
			log_print!("🏛️  Adding member to Tech Collective");
			log_print!("   👤 Member: {}", who.bright_cyan());
			log_print!("   🔑 Signed by: {}", from.bright_yellow());

			// Load wallet
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Submit transaction
			let tx_hash = add_member(&quantus_client, &keypair, &who, execution_mode).await?;

			log_print!(
				"✅ {} Add member transaction submitted! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);
		},

		TechCollectiveCommands::RemoveMember { who, from, password, password_file } => {
			log_print!("🏛️  Removing member from Tech Collective ");
			log_print!("   👤 Member: {}", who.bright_cyan());
			log_print!("   🔑 Signed by: {}", from.bright_yellow());

			// Load wallet
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Submit transaction
			let tx_hash = remove_member(&quantus_client, &keypair, &who, execution_mode).await?;

			log_print!(
				"✅ {} Remove member transaction submitted! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);
		},

		TechCollectiveCommands::Vote { referendum_index, aye, from, password, password_file } => {
			log_print!("🗳️  Voting on Tech Referendum #{} ", referendum_index);
			log_print!(
				"   📊 Vote: {}",
				if aye { "AYE ✅".bright_green() } else { "NAY ❌".bright_red() }
			);
			log_print!("   🔑 Signed by: {}", from.bright_yellow());

			// Load wallet
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Submit transaction
			let tx_hash = vote_on_referendum(
				&quantus_client,
				&keypair,
				referendum_index,
				aye,
				execution_mode,
			)
			.await?;

			log_print!(
				"✅ {} Vote transaction submitted! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);
		},

		TechCollectiveCommands::ListMembers => {
			log_print!("🏛️  Tech Collective Members ");
			log_print!("");

			// Get actual member list
			match get_member_list(&quantus_client).await {
				Ok(members) =>
					if members.is_empty() {
						log_print!("📭 No members in Tech Collective");
					} else {
						log_print!("👥 Total members: {}", members.len());
						log_print!("");

						for (index, member) in members.iter().enumerate() {
							log_print!(
								"{}. {}",
								(index + 1).to_string().bright_blue(),
								member.to_quantus_ss58().bright_green()
							);
						}
					},
				Err(e) => {
					log_verbose!("⚠️  Failed to get member list: {:?}", e);
					// Fallback to member count
					match get_member_count(&quantus_client).await? {
						Some(count_data) => {
							log_verbose!("✅ Got member count data: {:?}", count_data);
							if count_data > 0 {
								log_print!(
									"👥 Total members: {} (detailed list unavailable)",
									count_data
								);
							} else {
								log_print!("📭 No members in Tech Collective");
							}
						},
						None => {
							log_print!("📭 No member data found - Tech Collective may be empty");
						},
					}
				},
			}

			log_print!("");
			log_print!("💡 To check specific membership:");
			log_print!("   quantus tech-collective is-member --address <ADDRESS>");
			log_print!("💡 To add a member (requires sudo):");
			log_print!(
				"   quantus tech-collective add-member --who <ADDRESS> --from <SUDO_WALLET>"
			);
		},

		TechCollectiveCommands::IsMember { address } => {
			log_print!("🔍 Checking Tech Collective membership ");

			// Resolve address (could be wallet name or SS58 address)
			let resolved_address = resolve_address(&address)?;

			log_print!("   👤 Address: {}", resolved_address.bright_cyan());

			if is_member(&quantus_client, &resolved_address).await? {
				log_success!("✅ Address IS a member of Tech Collective!");
				log_print!("👥 Member data found in storage");
			} else {
				log_print!("❌ Address is NOT a member of Tech Collective");
				log_print!("💡 No membership record found for this address");
			}
		},

		TechCollectiveCommands::CheckSudo { address } => {
			log_print!("🏛️  Checking sudo permissions ");

			match get_sudo_account(&quantus_client).await? {
				Some(sudo_account) => {
					let sudo_address = sudo_account.to_quantus_ss58();
					log_verbose!("🔍 Found sudo account: {}", sudo_address);
					log_success!("✅ Found sudo account: {}", sudo_address.bright_green());

					// If an address was provided, check if it matches the sudo account
					if let Some(check_address) = address {
						log_verbose!("🔍 Checking if provided address is sudo...");

						// Resolve address (could be wallet name or SS58 address)
						let resolved_address = resolve_address(&check_address)?;
						log_verbose!("   👤 Address to check: {}", resolved_address);

						if sudo_address == resolved_address {
							log_success!("✅ Provided address IS the sudo account!");
						} else {
							log_print!("❌ Provided address is NOT the sudo account");
							log_verbose!("💡 Provided address: {}", resolved_address);
							log_verbose!("💡 Actual sudo address: {}", sudo_address);
						}
					} else {
						// No address provided, just show the sudo account
						log_verbose!("💡 Use 'quantus tech-collective check-sudo --address <ADDRESS>' to check if a specific address is sudo");
					}
				},
				None => {
					log_print!("📭 No sudo account found in network");
					log_verbose!("💡 The network may not have sudo configured");
				},
			}
		},

		TechCollectiveCommands::ListReferenda => {
			log_print!("📜 Active Tech Referenda ");
			log_print!("");

			log_print!("💡 Referenda listing requires TechReferenda pallet storage queries");
			log_print!(
                "💡 Use 'quantus call --pallet TechReferenda --call <method>' for direct interaction"
            );
		},

		TechCollectiveCommands::GetReferendum { index } => {
			log_print!("📄 Tech Referendum #{} Details ", index);
			log_print!("");

			log_print!("💡 Referendum details require TechReferenda storage access");
			log_print!("💡 Query ReferendumInfoFor storage with index {}", index);
		},
	};

	Ok(())
}
