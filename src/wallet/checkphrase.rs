/// Human-readable address checkphrase (qp-human-checkphrase).
///
/// Wordlist vendored from Quantus-Network/qp-human-checkphrase `final_wordlist.txt`
/// (v2.2.1); the crate only loads it from the current directory at runtime.
use std::sync::LazyLock;

static WORD_LIST: LazyLock<Vec<String>> = LazyLock::new(|| {
	let words: Vec<String> =
		include_str!("checkphrase_wordlist.txt").lines().map(str::to_string).collect();
	assert_eq!(words.len(), 2048, "embedded checkphrase wordlist must contain exactly 2048 words");
	words
});

/// Checkphrase for an address, e.g. "Word-Word-Word-Word-Word".
pub fn checkphrase(address: &str) -> String {
	qp_human_checkphrase::address_to_checksum(address, &WORD_LIST)
		.iter()
		.map(|word| {
			let mut chars = word.chars();
			match chars.next() {
				Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
				None => String::new(),
			}
		})
		.collect::<Vec<_>>()
		.join("-")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn checkphrase_is_deterministic_and_capitalized() {
		let address = "qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7";
		let phrase = checkphrase(address);
		assert_eq!(phrase, checkphrase(address));
		let words: Vec<&str> = phrase.split('-').collect();
		assert_eq!(words.len(), 5);
		for word in words {
			assert!(word.chars().next().unwrap().is_uppercase());
		}
	}

	#[test]
	fn different_addresses_differ() {
		assert_ne!(
			checkphrase("qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7"),
			checkphrase("qzkYEQv8tQsmniZYdame3Cku18RL5g9bGK9Pdydq5TMPdpE3y")
		);
	}
}
