use crate::chain::client::ChainClient;
use crate::error::Result;
use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::AccountId32;
use sp_core::crypto::Ss58Codec;
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::MultiAddress;
use substrate_api_client::ac_compose_macros::compose_extrinsic;
use substrate_api_client::{GetStorage, SubmitAndWatch};

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
    CheckSudo,

    /// List active Tech Referenda
    ListReferenda,

    /// Get details of a specific Tech Referendum
    GetReferendum {
        /// Referendum index
        #[arg(short, long)]
        index: u32,
    },
}

/// Handle tech collective command
pub async fn handle_tech_collective_command(
    command: TechCollectiveCommands,
    node_url: &str,
) -> Result<()> {
    match command {
        TechCollectiveCommands::AddMember {
            who,
            from,
            password,
            password_file,
        } => add_member(&who, &from, password, password_file, node_url).await,

        TechCollectiveCommands::RemoveMember {
            who,
            from,
            password,
            password_file,
        } => remove_member(&who, &from, password, password_file, node_url).await,

        TechCollectiveCommands::Vote {
            referendum_index,
            aye,
            from,
            password,
            password_file,
        } => {
            vote_on_referendum(
                referendum_index,
                aye,
                &from,
                password,
                password_file,
                node_url,
            )
            .await
        }

        TechCollectiveCommands::ListMembers => list_members(node_url).await,

        TechCollectiveCommands::IsMember { address } => is_member(&address, node_url).await,

        TechCollectiveCommands::CheckSudo => check_sudo(node_url).await,

        TechCollectiveCommands::ListReferenda => list_referenda(node_url).await,

        TechCollectiveCommands::GetReferendum { index } => {
            get_referendum_details(index, node_url).await
        }
    }
}

/// Add a member to the Tech Collective
async fn add_member(
    who: &str,
    from: &str,
    password: Option<String>,
    password_file: Option<String>,
    node_url: &str,
) -> Result<()> {
    log_print!("🏛️  Adding member to Tech Collective");
    log_print!("   👤 Member: {}", who.bright_cyan());
    log_print!("   🔑 Signed by: {}", from.bright_yellow());

    let chain_client = ChainClient::new(node_url).await?;
    let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

    // Parse the member address
    let member_account = AccountId32::from_ss58check(who).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid member address: {:?}", e))
    })?;
    let member: MultiAddress<AccountId32, u32> = MultiAddress::Id(member_account);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic with sudo wrapper for proper permissions
    // First create the inner call (TechCollective::add_member)
    let inner_call = compose_extrinsic!(&api_with_signer, "TechCollective", "add_member", member)
        .ok_or_else(|| {
        crate::error::QuantusError::Generic("Failed to create inner add_member call".to_string())
    })?;

    // Now wrap it with Sudo::sudo
    let extrinsic = compose_extrinsic!(&api_with_signer, "Sudo", "sudo", inner_call.function)
        .ok_or_else(|| {
            crate::error::QuantusError::Generic(
                "Failed to create sudo wrapper extrinsic".to_string(),
            )
        })?;

    // Submit transaction
    log_print!("📡 Submitting add_member transaction...");

    match crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic) {
        Ok(tx_report) => {
            log_success!("✅ Member added to Tech Collective successfully!");
            log_print!(
                "📋 Transaction hash: {}",
                tx_report.extrinsic_hash.to_string().bright_yellow()
            );
            Ok(())
        }
        Err(e) => {
            // Check if this is a BadOrigin error
            let error_msg = format!("{:?}", e);
            if error_msg.contains("BadOrigin") {
                log_error!("❌ BadOrigin error: Insufficient permissions to add member");
                log_print!("💡 TechCollective::add_member requires sudo permissions.");
                log_print!(
                    "💡 To add a member as sudo user, you need to create a proper sudo call."
                );
                log_print!("💡 Example workaround:");
                log_print!("   1. First, ensure you are sudo user (crystal_alice should be sudo in dev mode)");
                log_print!(
                    "   2. The call structure would be: Sudo::sudo(TechCollective::add_member)"
                );
                log_print!("   3. This requires manually encoding the inner call - complex implementation needed");
                log_print!("💡 Alternative: Check if the runtime has initial tech collective members set up");
                return Err(crate::error::QuantusError::Generic(
                    "add_member requires sudo permissions. The wallet used must have sudo access."
                        .to_string(),
                )
                .into());
            }
            Err(e)
        }
    }
}

/// Remove a member from the Tech Collective
async fn remove_member(
    who: &str,
    from: &str,
    password: Option<String>,
    password_file: Option<String>,
    node_url: &str,
) -> Result<()> {
    log_print!("🏛️  Removing member from Tech Collective");
    log_print!("   👤 Member: {}", who.bright_cyan());
    log_print!("   🔑 Signed by: {}", from.bright_yellow());

    let chain_client = ChainClient::new(node_url).await?;
    let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

    // Parse the member address
    let member_account = AccountId32::from_ss58check(who).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid member address: {:?}", e))
    })?;
    let member: MultiAddress<AccountId32, u32> = MultiAddress::Id(member_account);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic with sudo wrapper - if rank is provided, use it; otherwise let the runtime determine
    let inner_call = compose_extrinsic!(
        &api_with_signer,
        "TechCollective",
        "remove_member",
        member,
        0u16
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic("Failed to create inner remove_member call".to_string())
    })?;

    // Now wrap it with Sudo::sudo
    let extrinsic = compose_extrinsic!(&api_with_signer, "Sudo", "sudo", inner_call.function)
        .ok_or_else(|| {
            crate::error::QuantusError::Generic(
                "Failed to create sudo wrapper extrinsic".to_string(),
            )
        })?;

    // Submit transaction
    log_print!("📡 Submitting remove_member transaction...");
    let tx_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("✅ Member removed from Tech Collective successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// Vote on a Tech Referenda proposal
async fn vote_on_referendum(
    referendum_index: u32,
    aye: bool,
    from: &str,
    password: Option<String>,
    password_file: Option<String>,
    node_url: &str,
) -> Result<()> {
    log_print!("🗳️  Voting on Tech Referendum #{}", referendum_index);
    log_print!(
        "   📊 Vote: {}",
        if aye {
            "AYE ✅".bright_green()
        } else {
            "NAY ❌".bright_red()
        }
    );
    log_print!("   🔑 Signed by: {}", from.bright_yellow());

    let chain_client = ChainClient::new(node_url).await?;
    let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "TechCollective",
        "vote",
        referendum_index,
        aye
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic("Failed to create vote extrinsic".to_string())
    })?;

    // Submit transaction
    log_print!("📡 Submitting vote transaction...");
    let tx_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("✅ Vote submitted successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// List all Tech Collective members
async fn list_members(node_url: &str) -> Result<()> {
    log_print!("🏛️  Tech Collective Members");
    log_print!("");

    let chain_client = ChainClient::new(node_url).await?;
    let api = chain_client.get_api();

    // Query Members storage
    log_verbose!("🔍 Querying TechCollective Members storage...");

    // Get member count per rank - this is a Vec<u32> representing count per rank
    let member_count_result = api
        .get_storage::<Vec<u32>>("TechCollective", "MemberCount", None)
        .await;
    match member_count_result {
        Ok(Some(count_data)) => {
            log_verbose!("✅ Got member count data: {:?}", count_data);
            let total_members: u32 = count_data.iter().sum();
            if total_members > 0 {
                log_print!("👥 Total members: {}", total_members);
            } else {
                log_print!("📭 No members in Tech Collective");
            }
        }
        Ok(None) => {
            log_print!("📭 No member count data found - Tech Collective may be empty");
        }
        Err(e) => {
            log_verbose!("⚠️  Failed to query member count: {:?}", e);
        }
    }

    // List some storage keys to see if there are any members
    let storage_prefix = match api
        .get_storage_map_key_prefix("TechCollective", "Members")
        .await
    {
        Ok(prefix) => prefix,
        Err(e) => {
            log_verbose!("⚠️  Failed to get storage prefix: {:?}", e);
            return Ok(());
        }
    };
    let keys_result = api
        .get_storage_keys_paged(Some(storage_prefix.clone()), 10, None, None)
        .await;

    match keys_result {
        Ok(keys) => {
            if keys.is_empty() {
                log_print!("📭 No member keys found in storage");
            } else {
                log_print!("🔑 Found {} member storage keys", keys.len());
                log_verbose!("Storage keys: {:?}", keys);
            }
        }
        Err(e) => {
            log_verbose!("⚠️  Failed to query storage keys: {:?}", e);
        }
    }

    // For now, show placeholder with helpful information
    log_print!("");
    log_print!("💡 To check specific membership:");
    log_print!("   quantus tech-collective is-member --address <ADDRESS>");
    log_print!("💡 To add a member (requires sudo):");
    log_print!("   quantus tech-collective add-member --who <ADDRESS> --from <SUDO_WALLET>");

    Ok(())
}

/// Check if an address is a member
async fn is_member(address: &str, node_url: &str) -> Result<()> {
    log_print!("🔍 Checking Tech Collective membership");
    log_print!("   👤 Address: {}", address.bright_cyan());

    let chain_client = ChainClient::new(node_url).await?;
    let api = chain_client.get_api();

    // Parse the address
    let account = AccountId32::from_ss58check(address)
        .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e)))?;

    log_verbose!("🔍 Querying membership for: {:?}", account);

    // Query Members storage for this specific account
    // Members storage map: AccountId32 -> Option<MemberRecord>
    // We'll use a generic Vec<u8> for the member record since we don't know the exact type
    let member_result = api
        .get_storage_map::<AccountId32, Vec<u8>>("TechCollective", "Members", account, None)
        .await;

    match member_result {
        Ok(Some(member_data)) => {
            log_success!("✅ Address IS a member of Tech Collective!");
            log_print!("👥 Member data found in storage");
            log_verbose!("📊 Raw member data: {:?}", member_data);
            log_print!("💡 Raw data length: {} bytes", member_data.len());
        }
        Ok(None) => {
            log_print!("❌ Address is NOT a member of Tech Collective");
            log_print!("💡 No membership record found for this address");
        }
        Err(e) => {
            log_error!("❌ Failed to query membership: {:?}", e);
            log_print!("💡 Check if the node is accessible and the address is valid");
            return Err(crate::error::QuantusError::Generic(format!(
                "Storage query failed: {:?}",
                e
            ))
            .into());
        }
    }

    Ok(())
}

/// Check who has sudo permissions in the network
async fn check_sudo(node_url: &str) -> Result<()> {
    log_print!("🏛️  Checking who has sudo permissions in the network");

    let chain_client = ChainClient::new(node_url).await?;
    let api = chain_client.get_api();

    // Query sudo permissions
    log_verbose!("🔍 Querying sudo permissions...");

    let sudo_result = api.get_storage::<AccountId32>("Sudo", "Key", None).await;

    match sudo_result {
        Ok(Some(sudo_account)) => {
            log_success!(
                "✅ Found sudo account: {}",
                sudo_account.to_ss58check().bright_green()
            );
            log_print!("🔑 This account has root/sudo permissions");

            // Check if crystal_alice is the sudo account (get address dynamically)
            let crystal_alice_addr = dilithium_crypto::crystal_alice()
                .public()
                .into_account()
                .to_ss58check();
            if sudo_account.to_ss58check() == crystal_alice_addr {
                log_success!("✅ crystal_alice IS the sudo account!");
            } else {
                log_print!("❌ crystal_alice is NOT the sudo account");
                log_print!(
                    "💡 crystal_alice address: {}",
                    crystal_alice_addr.bright_cyan()
                );
                log_print!(
                    "💡 Actual sudo address: {}",
                    sudo_account.to_ss58check().bright_yellow()
                );
            }
        }
        Ok(None) => {
            log_print!("📭 No sudo account found in network");
            log_print!("💡 The network may not have sudo configured");
        }
        Err(e) => {
            log_error!("❌ Failed to query sudo account: {:?}", e);
            log_print!("💡 Check if the node is accessible and the network has sudo configured");
        }
    }

    Ok(())
}

/// List active Tech Referenda
async fn list_referenda(node_url: &str) -> Result<()> {
    log_print!("📜 Active Tech Referenda");
    log_print!("");

    let _chain_client = ChainClient::new(node_url).await?;

    log_print!("💡 Referenda listing requires TechReferenda pallet storage queries");
    log_print!(
        "💡 Use 'quantus call --pallet TechReferenda --call <method>' for direct interaction"
    );

    Ok(())
}

/// Get referendum details
async fn get_referendum_details(index: u32, node_url: &str) -> Result<()> {
    log_print!("📄 Tech Referendum #{} Details", index);
    log_print!("");

    let _chain_client = ChainClient::new(node_url).await?;

    log_print!("💡 Referendum details require TechReferenda storage access");
    log_print!("💡 Query ReferendumInfoFor storage with index {}", index);

    Ok(())
}
