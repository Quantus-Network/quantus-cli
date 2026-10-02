//! `quantus near contract …` — near-cli-rs's `contract call-function` sentence, signed by a
//! Quantus ML-DSA-65 wallet.
//!
//! The grammar copies near-cli-rs word for word, so a script written for one runs on the other
//! with `sign-with-keychain` swapped for `sign-with-wallet <WALLET>`:
//!
//! ```text
//! quantus near contract call-function as-read-only <CONTRACT> <METHOD> json-args <ARGS> \
//!     network-config <NET> now
//! quantus near contract call-function as-transaction <CONTRACT> <METHOD> json-args <ARGS> \
//!     prepaid-gas '30 Tgas' attached-deposit '1 yoctoNEAR' sign-as <ACCOUNT> \
//!     network-config <NET> sign-with-wallet <WALLET> send|display
//! ```
//!
//! `<NET>` is `mainnet`, `testnet` or an RPC URL. `display` prints the transaction and the
//! equivalent near-cli-rs command without loading the wallet or touching the network.

use crate::{
	cli::{
		near::{load_ml_dsa_65_wallet, report_outcome, submit_function_call},
		send::{format_balance, parse_amount_with_decimals},
	},
	error::{QuantusError, Result},
	log_print, log_success,
	near::{
		protocol::{validate_account_id, NEAR_DECIMALS},
		rpc::{decode_success_value, NearRpcClient},
	},
};
use clap::Subcommand;
use colored::Colorize;

#[derive(Subcommand, Debug)]
pub enum ContractCommands {
	/// Execute function (contract method)
	CallFunction {
		#[command(subcommand)]
		mode: CallFunctionMode,
	},
}

#[derive(Subcommand, Debug)]
pub enum CallFunctionMode {
	/// Calling a view method
	AsReadOnly {
		/// What is the contract account ID?
		contract_account_id: String,
		/// What is the name of the function?
		function_name: String,
		#[command(subcommand)]
		args: ReadOnlyArgs,
	},
	/// Calling a change method
	AsTransaction {
		/// What is the contract account ID?
		contract_account_id: String,
		/// What is the name of the function?
		function_name: String,
		#[command(subcommand)]
		args: TransactionArgs,
	},
}

#[derive(Subcommand, Debug)]
pub enum ReadOnlyArgs {
	/// Valid JSON arguments (e.g. {"token_id": "42"})
	JsonArgs {
		function_args: String,
		#[command(subcommand)]
		network: ReadOnlyNetwork,
	},
}

#[derive(Subcommand, Debug)]
pub enum ReadOnlyNetwork {
	/// Select network
	NetworkConfig {
		/// mainnet, testnet, or an RPC URL
		network_name: String,
		#[command(subcommand)]
		block: ReadOnlyBlock,
	},
}

#[derive(Subcommand, Debug)]
pub enum ReadOnlyBlock {
	/// View properties in the final block
	Now,
}

#[derive(Subcommand, Debug)]
pub enum TransactionArgs {
	/// Valid JSON arguments (e.g. {"token_id": "42"})
	JsonArgs {
		function_args: String,
		#[command(subcommand)]
		gas: GasStep,
	},
}

#[derive(Subcommand, Debug)]
pub enum GasStep {
	/// Enter gas for function call
	PrepaidGas {
		/// e.g. '30 Tgas'
		gas: String,
		#[command(subcommand)]
		deposit: DepositStep,
	},
}

#[derive(Subcommand, Debug)]
pub enum DepositStep {
	/// Enter deposit for a function call
	AttachedDeposit {
		/// e.g. '1 yoctoNEAR' or '0.5 NEAR'
		deposit: String,
		#[command(subcommand)]
		signer: SignerStep,
	},
}

#[derive(Subcommand, Debug)]
pub enum SignerStep {
	/// What is the signer account ID?
	SignAs {
		signer_account_id: String,
		#[command(subcommand)]
		network: TransactionNetwork,
	},
}

#[derive(Subcommand, Debug)]
pub enum TransactionNetwork {
	/// Select network
	NetworkConfig {
		/// mainnet, testnet, or an RPC URL
		network_name: String,
		#[command(subcommand)]
		signer: SignWithStep,
	},
}

#[derive(Subcommand, Debug)]
pub enum SignWithStep {
	/// Sign the transaction with a Quantus ML-DSA-65 wallet
	SignWithWallet {
		/// Quantus wallet holding the signer account's ML-DSA-65 key
		wallet: String,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		#[command(subcommand)]
		submit: Submit,
	},
}

#[derive(Subcommand, Debug)]
pub enum Submit {
	/// Send the transaction to the network
	Send,
	/// Print the transaction and the equivalent near-cli-rs command without signing or sending
	Display,
}

pub async fn handle_contract_command(command: ContractCommands) -> Result<()> {
	let ContractCommands::CallFunction { mode } = command;
	match mode {
		CallFunctionMode::AsReadOnly {
			contract_account_id,
			function_name,
			args:
				ReadOnlyArgs::JsonArgs {
					function_args,
					network:
						ReadOnlyNetwork::NetworkConfig { network_name, block: ReadOnlyBlock::Now },
				},
		} =>
			call_as_read_only(&contract_account_id, &function_name, &function_args, &network_name)
				.await,
		CallFunctionMode::AsTransaction {
			contract_account_id,
			function_name,
			args:
				TransactionArgs::JsonArgs {
					function_args,
					gas:
						GasStep::PrepaidGas {
							gas,
							deposit:
								DepositStep::AttachedDeposit {
									deposit,
									signer:
										SignerStep::SignAs {
											signer_account_id,
											network:
												TransactionNetwork::NetworkConfig {
													network_name,
													signer:
														SignWithStep::SignWithWallet {
															wallet,
															password,
															password_file,
															submit,
														},
												},
										},
								},
						},
				},
		} =>
			call_as_transaction(
				FunctionCall {
					contract: contract_account_id,
					method: function_name,
					args: function_args,
					gas,
					deposit,
					signer: signer_account_id,
					network: network_name,
				},
				&wallet,
				password,
				password_file,
				submit,
			)
			.await,
	}
}

/// One `as-transaction` sentence, with the amounts still as the user typed them.
struct FunctionCall {
	contract: String,
	method: String,
	args: String,
	gas: String,
	deposit: String,
	signer: String,
	network: String,
}

async fn call_as_read_only(contract: &str, method: &str, args: &str, network: &str) -> Result<()> {
	validate_account_id(contract)?;
	let args = parse_json_args(args)?;
	let client = NearRpcClient::for_network(network, None)?;
	let value = client.call_view_function(contract, method, &args).await?;
	log_print!("{}", pretty_json(&value));
	Ok(())
}

async fn call_as_transaction(
	call: FunctionCall,
	wallet: &str,
	password: Option<String>,
	password_file: Option<String>,
	submit: Submit,
) -> Result<()> {
	validate_account_id(&call.contract)?;
	validate_account_id(&call.signer)?;
	let args = parse_json_args(&call.args)?;
	let gas = parse_gas(&call.gas)?;
	let deposit = parse_deposit(&call.deposit)?;

	log_print!("Unsigned transaction:");
	log_print!("   signer_id:    {}", call.signer.bright_cyan());
	log_print!("   receiver_id:  {}", call.contract.bright_cyan());
	log_print!("   actions:");
	log_print!("      -- function call:");
	log_print!("                      method name:  {}", call.method);
	log_print!(
		"                      args:         {}",
		pretty_json(&args).replace('\n', "\n                                    ")
	);
	log_print!("                      gas:          {} Tgas", format_balance(u128::from(gas), 12));
	log_print!("                      deposit:      {}", format_deposit(deposit));

	if let Submit::Display = submit {
		log_print!("");
		log_print!("near-cli-rs equivalent:");
		log_print!("   {}", near_cli_line(&call, &args));
		return Ok(());
	}

	let (keypair, public) = load_ml_dsa_65_wallet(wallet, password, password_file)?;
	let client = NearRpcClient::for_network(&call.network, None)?;
	client.ensure_ml_dsa_support().await?;

	log_print!("");
	log_print!(
		"📡 Calling {}.{} as {} (ML-DSA-65 wallet '{wallet}')",
		call.contract.bright_cyan(),
		call.method,
		call.signer.bright_cyan()
	);
	let outcome = submit_function_call(
		&client,
		&keypair,
		public,
		&call.signer,
		&call.contract,
		&call.method,
		args.to_string().into_bytes(),
		gas,
		deposit,
		&call.network,
	)
	.await?;
	report_outcome(&call.network, &outcome);
	print_logs(&outcome);
	match decode_success_value(&outcome) {
		Some(value) => log_print!("Function execution return value:\n{}", pretty_json(&value)),
		None => log_print!("Function execution return value: (empty)"),
	}
	log_success!(
		"✅ The \"{}\" call to <{}> on behalf of <{}> succeeded.",
		call.method,
		call.contract,
		call.signer
	);
	Ok(())
}

fn print_logs(outcome: &serde_json::Value) {
	let Some(receipts) = outcome.get("receipts_outcome").and_then(|r| r.as_array()) else {
		return;
	};
	for receipt in receipts {
		let executor =
			receipt.pointer("/outcome/executor_id").and_then(|e| e.as_str()).unwrap_or("?");
		let logs = receipt
			.pointer("/outcome/logs")
			.and_then(|l| l.as_array())
			.map(|l| l.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
			.unwrap_or_default();
		if !logs.is_empty() {
			log_print!("Logs [{executor}]:");
			for log in logs {
				log_print!("   {log}");
			}
		}
	}
}

/// The same call as near-cli-rs would take it, signing from its keychain.
fn near_cli_line(call: &FunctionCall, args: &serde_json::Value) -> String {
	format!(
		"near contract call-function as-transaction {} {} json-args {} prepaid-gas {} attached-deposit {} sign-as {} network-config {} sign-with-keychain send",
		call.contract,
		call.method,
		shell_quote(&args.to_string()),
		shell_quote(&call.gas),
		shell_quote(&call.deposit),
		call.signer,
		call.network
	)
}

fn shell_quote(text: &str) -> String {
	format!("'{}'", text.replace('\'', "'\\''"))
}

fn pretty_json(value: &serde_json::Value) -> String {
	serde_json::to_string_pretty(value).expect("JSON value serialises")
}

fn parse_json_args(text: &str) -> Result<serde_json::Value> {
	serde_json::from_str(text).map_err(|e| QuantusError::Generic(format!("json-args: {e}")))
}

/// `parse_amount_with_decimals` refuses zero; a zero deposit is a valid near-cli value.
fn parse_units(amount: &str, decimals: u8) -> Result<u128> {
	if !amount.is_empty() && amount.chars().all(|c| c == '0' || c == '.') {
		return Ok(0);
	}
	parse_amount_with_decimals(amount, decimals)
}

fn split_unit(text: &str) -> Result<(&str, &str)> {
	let mut parts = text.split_whitespace();
	match (parts.next(), parts.next(), parts.next()) {
		(Some(amount), Some(unit), None) => Ok((amount, unit)),
		_ => Err(QuantusError::Generic(format!(
			"'{text}' must be '<amount> <unit>', e.g. '30 Tgas' or '0.5 NEAR'"
		))),
	}
}

/// `'30 Tgas'` → gas units.
fn parse_gas(text: &str) -> Result<u64> {
	let (amount, unit) = split_unit(text)?;
	if !unit.eq_ignore_ascii_case("tgas") {
		return Err(QuantusError::Generic(format!(
			"gas '{text}' must be given in Tgas, e.g. '30 Tgas'"
		)));
	}
	let gas = parse_units(amount, 12)?;
	u64::try_from(gas).map_err(|_| QuantusError::Generic(format!("gas '{text}' is out of range")))
}

/// `'0.5 NEAR'` or `'1 yoctoNEAR'` → yoctoNEAR.
fn parse_deposit(text: &str) -> Result<u128> {
	let (amount, unit) = split_unit(text)?;
	match unit.to_ascii_lowercase().as_str() {
		"near" => parse_units(amount, NEAR_DECIMALS),
		"yoctonear" => parse_units(amount, 0),
		_ => Err(QuantusError::Generic(format!(
			"deposit '{text}' must be in NEAR or yoctoNEAR, e.g. '0.5 NEAR' or '1 yoctoNEAR'"
		))),
	}
}

fn format_deposit(yocto: u128) -> String {
	if yocto < 1_000_000_000_000 {
		format!("{yocto} yoctoNEAR")
	} else {
		format!("{} NEAR", format_balance(yocto, NEAR_DECIMALS))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use clap::Parser;

	#[derive(Parser)]
	struct Cli {
		#[command(subcommand)]
		contract: ContractCommands,
	}

	#[test]
	fn the_near_cli_transaction_sentence_parses() {
		let cli = Cli::try_parse_from([
			"quantus-near",
			"call-function",
			"as-transaction",
			"dclv2.ref-labs.near",
			"create_pool",
			"json-args",
			r#"{"fee":2000}"#,
			"prepaid-gas",
			"180 Tgas",
			"attached-deposit",
			"0.1 NEAR",
			"sign-as",
			"alice.near",
			"network-config",
			"mainnet",
			"sign-with-wallet",
			"vault",
			"--password-file",
			"/tmp/pw",
			"send",
		])
		.unwrap();
		let ContractCommands::CallFunction {
			mode: CallFunctionMode::AsTransaction { contract_account_id, function_name, args },
		} = cli.contract
		else {
			panic!("as-transaction");
		};
		assert_eq!(contract_account_id, "dclv2.ref-labs.near");
		assert_eq!(function_name, "create_pool");
		let TransactionArgs::JsonArgs { function_args, gas: GasStep::PrepaidGas { gas, deposit } } =
			args;
		assert_eq!(function_args, r#"{"fee":2000}"#);
		assert_eq!(gas, "180 Tgas");
		let DepositStep::AttachedDeposit {
			deposit,
			signer: SignerStep::SignAs { signer_account_id, network },
		} = deposit;
		assert_eq!(deposit, "0.1 NEAR");
		assert_eq!(signer_account_id, "alice.near");
		let TransactionNetwork::NetworkConfig {
			network_name,
			signer: SignWithStep::SignWithWallet { wallet, password_file, submit, .. },
		} = network;
		assert_eq!(network_name, "mainnet");
		assert_eq!(wallet, "vault");
		assert_eq!(password_file.as_deref(), Some("/tmp/pw"));
		assert!(matches!(submit, Submit::Send));
	}

	#[test]
	fn the_near_cli_read_only_sentence_parses() {
		let cli = Cli::try_parse_from([
			"quantus-near",
			"call-function",
			"as-read-only",
			"dclv2.ref-labs.near",
			"get_pool",
			"json-args",
			r#"{"pool_id":"a|b|2000"}"#,
			"network-config",
			"testnet",
			"now",
		])
		.unwrap();
		let ContractCommands::CallFunction {
			mode:
				CallFunctionMode::AsReadOnly {
					args:
						ReadOnlyArgs::JsonArgs {
							network: ReadOnlyNetwork::NetworkConfig { network_name, .. },
							..
						},
					..
				},
		} = cli.contract
		else {
			panic!("as-read-only");
		};
		assert_eq!(network_name, "testnet");
	}

	#[test]
	fn a_sentence_with_a_missing_step_is_rejected() {
		let missing_submit = Cli::try_parse_from([
			"quantus-near",
			"call-function",
			"as-transaction",
			"c.near",
			"m",
			"json-args",
			"{}",
			"prepaid-gas",
			"30 Tgas",
			"attached-deposit",
			"0 NEAR",
			"sign-as",
			"a.near",
			"network-config",
			"mainnet",
			"sign-with-wallet",
			"w",
		]);
		assert!(missing_submit.is_err());
		let wrong_order = Cli::try_parse_from([
			"quantus-near",
			"call-function",
			"as-transaction",
			"c.near",
			"m",
			"json-args",
			"{}",
			"attached-deposit",
			"0 NEAR",
			"prepaid-gas",
			"30 Tgas",
		]);
		assert!(wrong_order.is_err());
	}

	#[test]
	fn gas_and_deposit_use_near_cli_units() {
		assert_eq!(parse_gas("30 Tgas").unwrap(), 30_000_000_000_000);
		assert_eq!(parse_gas("0.5 TGas").unwrap(), 500_000_000_000);
		assert!(parse_gas("30").is_err());
		assert!(parse_gas("30 gas").is_err());

		assert_eq!(parse_deposit("1 yoctoNEAR").unwrap(), 1);
		assert_eq!(parse_deposit("10000 yoctonear").unwrap(), 10_000);
		assert_eq!(parse_deposit("0.5 NEAR").unwrap(), 500_000_000_000_000_000_000_000);
		assert_eq!(parse_deposit("0 NEAR").unwrap(), 0);
		assert!(parse_deposit("1.5 yoctoNEAR").is_err());
		assert!(parse_deposit("1 QTC").is_err());
		assert!(parse_deposit("1").is_err());

		assert_eq!(format_deposit(1), "1 yoctoNEAR");
		assert_eq!(format_deposit(1_250_000_000_000_000_000_000), "0.00125 NEAR");
		assert_eq!(format_deposit(10u128.pow(24)), "1 NEAR");
	}

	#[test]
	fn near_cli_line_round_trips_the_sentence() {
		let call = FunctionCall {
			contract: "qtc.omft.near".into(),
			method: "ft_transfer_call".into(),
			args: String::new(),
			gas: "150 Tgas".into(),
			deposit: "1 yoctoNEAR".into(),
			signer: "alice.near".into(),
			network: "mainnet".into(),
		};
		let args = serde_json::json!({ "receiver_id": "dclv2.ref-labs.near", "amount": "1", "msg": "\"Deposit\"" });
		assert_eq!(
			near_cli_line(&call, &args),
			r#"near contract call-function as-transaction qtc.omft.near ft_transfer_call json-args '{"amount":"1","msg":"\"Deposit\"","receiver_id":"dclv2.ref-labs.near"}' prepaid-gas '150 Tgas' attached-deposit '1 yoctoNEAR' sign-as alice.near network-config mainnet sign-with-keychain send"#
		);
		assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);
	}

	#[test]
	fn json_args_must_be_json() {
		assert!(parse_json_args("{}").is_ok());
		assert!(parse_json_args(r#"{"a":1}"#).is_ok());
		assert!(parse_json_args("{a:1}").is_err());
	}
}
