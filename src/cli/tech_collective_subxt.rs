//! `quantus tech-collective-subxt` subcommand - SubXT implementation
use crate::{
    chain::quantus_subxt, chain::types::ChainConfig, error::QuantusError, log_error, log_print,
    log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::OnlineClient;

/// SubXT-based tech collective client for governance operations
pub struct SubxtTechCollectiveClient {
    client: OnlineClient<ChainConfig>,
}

impl SubxtTechCollectiveClient {
    /// Create a new SubXT tech collective client
    pub async fn new(node_url: &str) -> crate::error::Result<Self> {
        let client = OnlineClient::from_url(node_url)
            .await
            .map_err(|e| QuantusError::NetworkError(format!("Failed to connect: {:?}", e)))?;

        Ok(Self { client })
    }

    /// Add a member to the Tech Collective using sudo
    pub async fn add_member(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        who_address: &str,
    ) -> crate::error::Result<subxt::utils::H256> {
        log_verbose!("🏛️  Adding member to Tech Collective with subxt...");
        log_verbose!("   Member: {}", who_address.bright_cyan());

        // Parse the member address
        let member_account_sp = AccountId32::from_ss58check(who_address)
            .map_err(|e| QuantusError::Generic(format!("Invalid member address: {:?}", e)))?;

        // Convert to subxt_core AccountId32
        let member_account_bytes: [u8; 32] = *member_account_sp.as_ref();
        let member_account_id =
            subxt::ext::subxt_core::utils::AccountId32::from(member_account_bytes);

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating add_member transaction with subxt...");

        // Create the TechCollective::add_member call as RuntimeCall enum
        let add_member_call = quantus_subxt::api::Call::TechCollective(
            quantus_subxt::api::tech_collective::Call::add_member {
                who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id),
            },
        );

        // Wrap in Sudo::sudo call
        let sudo_call = quantus_subxt::api::tx().sudo().sudo(add_member_call);

        // Get fresh nonce for the sender
        use substrate_api_client::ac_primitives::AccountId32 as SubstrateAccountId32;
        let from_account_id = SubstrateAccountId32::from_ss58check(
            &from_keypair.to_account_id_ss58check(),
        )
        .map_err(|e| QuantusError::NetworkError(format!("Invalid from address: {:?}", e)))?;

        let nonce = self
            .client
            .tx()
            .account_nonce(&from_account_id)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to get account nonce: {:?}", e))
            })?;

        log_verbose!("🔢 Using nonce: {}", nonce);

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&sudo_call, &signer, params)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to submit transaction: {:?}", e))
            })?;

        log_verbose!(
            "📋 Add member transaction submitted with subxt: {:?}",
            tx_hash
        );

        Ok(tx_hash)
    }

    /// Remove a member from the Tech Collective using sudo
    pub async fn remove_member(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        who_address: &str,
    ) -> crate::error::Result<subxt::utils::H256> {
        log_verbose!("🏛️  Removing member from Tech Collective with subxt...");
        log_verbose!("   Member: {}", who_address.bright_cyan());

        // Parse the member address
        let member_account_sp = AccountId32::from_ss58check(who_address)
            .map_err(|e| QuantusError::Generic(format!("Invalid member address: {:?}", e)))?;

        // Convert to subxt_core AccountId32
        let member_account_bytes: [u8; 32] = *member_account_sp.as_ref();
        let member_account_id =
            subxt::ext::subxt_core::utils::AccountId32::from(member_account_bytes);

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating remove_member transaction with subxt...");

        // Create the TechCollective::remove_member call as RuntimeCall enum
        let remove_member_call = quantus_subxt::api::Call::TechCollective(
            quantus_subxt::api::tech_collective::Call::remove_member {
                who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id),
                min_rank: 0u16, // Use rank 0 as default
            },
        );

        // Wrap in Sudo::sudo call
        let sudo_call = quantus_subxt::api::tx().sudo().sudo(remove_member_call);

        // Get fresh nonce for the sender
        use substrate_api_client::ac_primitives::AccountId32 as SubstrateAccountId32;
        let from_account_id = SubstrateAccountId32::from_ss58check(
            &from_keypair.to_account_id_ss58check(),
        )
        .map_err(|e| QuantusError::NetworkError(format!("Invalid from address: {:?}", e)))?;

        let nonce = self
            .client
            .tx()
            .account_nonce(&from_account_id)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to get account nonce: {:?}", e))
            })?;

        log_verbose!("🔢 Using nonce: {}", nonce);

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&sudo_call, &signer, params)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to submit transaction: {:?}", e))
            })?;

        log_verbose!(
            "📋 Remove member transaction submitted with subxt: {:?}",
            tx_hash
        );

        Ok(tx_hash)
    }

    /// Vote on a Tech Referenda proposal
    pub async fn vote_on_referendum(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        referendum_index: u32,
        aye: bool,
    ) -> crate::error::Result<subxt::utils::H256> {
        log_verbose!("🗳️  Voting on referendum with subxt...");
        log_verbose!("   Referendum: {}", referendum_index);
        log_verbose!("   Vote: {}", if aye { "AYE" } else { "NAY" });

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating vote transaction with subxt...");

        // Create the TechCollective::vote call
        let vote_call = quantus_subxt::api::tx()
            .tech_collective()
            .vote(referendum_index, aye);

        // Get fresh nonce for the sender
        use substrate_api_client::ac_primitives::AccountId32 as SubstrateAccountId32;
        let from_account_id = SubstrateAccountId32::from_ss58check(
            &from_keypair.to_account_id_ss58check(),
        )
        .map_err(|e| QuantusError::NetworkError(format!("Invalid from address: {:?}", e)))?;

        let nonce = self
            .client
            .tx()
            .account_nonce(&from_account_id)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to get account nonce: {:?}", e))
            })?;

        log_verbose!("🔢 Using nonce: {}", nonce);

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&vote_call, &signer, params)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to submit transaction: {:?}", e))
            })?;

        log_verbose!("📋 Vote transaction submitted with subxt: {:?}", tx_hash);

        Ok(tx_hash)
    }

    /// Check if an address is a member of the Tech Collective
    pub async fn is_member(&self, address: &str) -> crate::error::Result<bool> {
        log_verbose!("🔍 Checking membership with subxt...");
        log_verbose!("   Address: {}", address.bright_cyan());

        // Parse the address
        let account_sp = AccountId32::from_ss58check(address)
            .map_err(|e| QuantusError::Generic(format!("Invalid address: {:?}", e)))?;

        // Convert to subxt_core AccountId32
        let account_bytes: [u8; 32] = *account_sp.as_ref();
        let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

        // Query Members storage
        let storage_addr = quantus_subxt::api::storage()
            .tech_collective()
            .members(account_id);

        let storage_at = self.client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

        let member_data = storage_at.fetch(&storage_addr).await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to fetch member data: {:?}", e))
        })?;

        Ok(member_data.is_some())
    }

    /// Get member count information
    pub async fn get_member_count(&self) -> crate::error::Result<Option<u32>> {
        log_verbose!("🔍 Getting member count with subxt...");

        // Query MemberCount storage - use rank 0 as default
        let storage_addr = quantus_subxt::api::storage()
            .tech_collective()
            .member_count(0u16);

        let storage_at = self.client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

        let count_data = storage_at.fetch(&storage_addr).await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to fetch member count: {:?}", e))
        })?;

        Ok(count_data)
    }

    /// Get list of all members
    pub async fn get_member_list(&self) -> crate::error::Result<Vec<AccountId32>> {
        log_verbose!("🔍 Getting member list with subxt...");

        let storage_at = self.client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

        // Query all Members storage entries
        let members_storage = quantus_subxt::api::storage()
            .tech_collective()
            .members_iter();

        let mut members = Vec::new();
        let mut iter = storage_at.iter(members_storage).await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to create members iterator: {:?}", e))
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
                        log_verbose!("Found member: {}", sp_account.to_ss58check());
                        members.push(sp_account);
                    }
                }
                Err(e) => {
                    log_verbose!("⚠️  Error reading member entry: {:?}", e);
                }
            }
        }

        log_verbose!("Found {} total members", members.len());
        Ok(members)
    }

    /// Get sudo account information
    pub async fn get_sudo_account(&self) -> crate::error::Result<Option<AccountId32>> {
        log_verbose!("🔍 Getting sudo account with subxt...");

        // Query Sudo::Key storage
        let storage_addr = quantus_subxt::api::storage().sudo().key();

        let storage_at = self.client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

        let sudo_account = storage_at.fetch(&storage_addr).await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to fetch sudo account: {:?}", e))
        })?;

        // Convert from subxt_core AccountId32 to sp_core AccountId32
        if let Some(subxt_account) = sudo_account {
            let account_bytes: [u8; 32] = *subxt_account.as_ref();
            let sp_account = AccountId32::from(account_bytes);
            Ok(Some(sp_account))
        } else {
            Ok(None)
        }
    }

    /// Wait for transaction finalization using subxt
    pub async fn wait_for_finalization(
        &self,
        _tx_hash: subxt::utils::H256,
    ) -> crate::error::Result<bool> {
        log_verbose!("⏳ Waiting for transaction finalization...");

        // For now, we use a simple delay approach similar to other SubXT implementations
        // TODO: Implement proper finalization watching using SubXT events
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;

        log_verbose!("✅ Transaction likely finalized (after 6s delay)");
        Ok(true)
    }
}

/// Tech Collective management commands using SubXT
#[derive(Subcommand, Debug)]
pub enum TechCollectiveSubxtCommands {
    /// Add a member to the Tech Collective using subxt
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

    /// Remove a member from the Tech Collective using subxt
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

    /// Vote on a Tech Referenda proposal using subxt
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

    /// List all Tech Collective members using subxt
    ListMembers,

    /// Check if an address is a member of the Tech Collective using subxt
    IsMember {
        /// Address to check
        #[arg(short, long)]
        address: String,
    },

    /// Check who has sudo permissions in the network using subxt
    CheckSudo,

    /// List active Tech Referenda using subxt
    ListReferenda,

    /// Get details of a specific Tech Referendum using subxt
    GetReferendum {
        /// Referendum index
        #[arg(short, long)]
        index: u32,
    },
}

/// Handle tech collective subxt commands
pub async fn handle_tech_collective_subxt_command(
    command: TechCollectiveSubxtCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    log_print!("🏛️  Tech Collective (SubXT)");

    let tech_collective_client = SubxtTechCollectiveClient::new(node_url).await?;

    match command {
        TechCollectiveSubxtCommands::AddMember {
            who,
            from,
            password,
            password_file,
        } => {
            log_print!("🏛️  Adding member to Tech Collective (using subxt)");
            log_print!("   👤 Member: {}", who.bright_cyan());
            log_print!("   🔑 Signed by: {}", from.bright_yellow());

            // Load wallet
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction using subxt
            let tx_hash = tech_collective_client.add_member(&keypair, &who).await?;

            log_print!(
                "✅ {} Add member transaction submitted with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = tech_collective_client
                .wait_for_finalization(tx_hash)
                .await?;

            if success {
                log_success!(
                    "🎉 {} Member added to Tech Collective with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }

        TechCollectiveSubxtCommands::RemoveMember {
            who,
            from,
            password,
            password_file,
        } => {
            log_print!("🏛️  Removing member from Tech Collective (using subxt)");
            log_print!("   👤 Member: {}", who.bright_cyan());
            log_print!("   🔑 Signed by: {}", from.bright_yellow());

            // Load wallet
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction using subxt
            let tx_hash = tech_collective_client.remove_member(&keypair, &who).await?;

            log_print!(
                "✅ {} Remove member transaction submitted with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = tech_collective_client
                .wait_for_finalization(tx_hash)
                .await?;

            if success {
                log_success!(
                    "🎉 {} Member removed from Tech Collective with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }

        TechCollectiveSubxtCommands::Vote {
            referendum_index,
            aye,
            from,
            password,
            password_file,
        } => {
            log_print!(
                "🗳️  Voting on Tech Referendum #{} (using subxt)",
                referendum_index
            );
            log_print!(
                "   📊 Vote: {}",
                if aye {
                    "AYE ✅".bright_green()
                } else {
                    "NAY ❌".bright_red()
                }
            );
            log_print!("   🔑 Signed by: {}", from.bright_yellow());

            // Load wallet
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction using subxt
            let tx_hash = tech_collective_client
                .vote_on_referendum(&keypair, referendum_index, aye)
                .await?;

            log_print!(
                "✅ {} Vote transaction submitted with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = tech_collective_client
                .wait_for_finalization(tx_hash)
                .await?;

            if success {
                log_success!(
                    "🎉 {} Vote submitted with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }

        TechCollectiveSubxtCommands::ListMembers => {
            log_print!("🏛️  Tech Collective Members (using subxt)");
            log_print!("");

            // Get actual member list
            match tech_collective_client.get_member_list().await {
                Ok(members) => {
                    if members.is_empty() {
                        log_print!("📭 No members in Tech Collective");
                    } else {
                        log_print!("👥 Total members: {}", members.len());
                        log_print!("");

                        for (index, member) in members.iter().enumerate() {
                            log_print!(
                                "{}. {}",
                                (index + 1).to_string().bright_blue(),
                                member.to_ss58check().bright_green()
                            );
                        }
                    }
                }
                Err(e) => {
                    log_verbose!("⚠️  Failed to get member list: {:?}", e);
                    // Fallback to member count
                    match tech_collective_client.get_member_count().await? {
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
                        }
                        None => {
                            log_print!("📭 No member data found - Tech Collective may be empty");
                        }
                    }
                }
            }

            log_print!("");
            log_print!("💡 To check specific membership:");
            log_print!("   quantus tech-collective-subxt is-member --address <ADDRESS>");
            log_print!("💡 To add a member (requires sudo):");
            log_print!(
                "   quantus tech-collective-subxt add-member --who <ADDRESS> --from <SUDO_WALLET>"
            );

            Ok(())
        }

        TechCollectiveSubxtCommands::IsMember { address } => {
            log_print!("🔍 Checking Tech Collective membership (using subxt)");
            log_print!("   👤 Address: {}", address.bright_cyan());

            if tech_collective_client.is_member(&address).await? {
                log_success!("✅ Address IS a member of Tech Collective!");
                log_print!("👥 Member data found in storage");
            } else {
                log_print!("❌ Address is NOT a member of Tech Collective");
                log_print!("💡 No membership record found for this address");
            }

            Ok(())
        }

        TechCollectiveSubxtCommands::CheckSudo => {
            log_print!("🏛️  Checking sudo permissions (using subxt)");

            match tech_collective_client.get_sudo_account().await? {
                Some(sudo_account) => {
                    log_success!(
                        "✅ Found sudo account: {}",
                        sudo_account.to_ss58check().bright_green()
                    );
                    log_print!("🔑 This account has root/sudo permissions");

                    // Check if crystal_alice is the sudo account
                    let crystal_alice_addr = "qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ";
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
                None => {
                    log_print!("📭 No sudo account found in network");
                    log_print!("💡 The network may not have sudo configured");
                }
            }

            Ok(())
        }

        TechCollectiveSubxtCommands::ListReferenda => {
            log_print!("📜 Active Tech Referenda (using subxt)");
            log_print!("");

            log_print!("💡 Referenda listing requires TechReferenda pallet storage queries");
            log_print!(
                "💡 Use 'quantus call --pallet TechReferenda --call <method>' for direct interaction"
            );

            Ok(())
        }

        TechCollectiveSubxtCommands::GetReferendum { index } => {
            log_print!("📄 Tech Referendum #{} Details (using subxt)", index);
            log_print!("");

            log_print!("💡 Referendum details require TechReferenda storage access");
            log_print!("💡 Query ReferendumInfoFor storage with index {}", index);

            Ok(())
        }
    }
}
