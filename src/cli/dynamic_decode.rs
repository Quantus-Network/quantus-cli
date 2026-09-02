//! Helpers for reading chain state that the generated codegen cannot decode.
//!
//! The types in [`crate::chain::quantus_subxt`] are generated from one runtime's
//! metadata. Any storage entry whose type graph reaches a runtime-composed type —
//! `OriginCaller`, `RuntimeCall`, a runtime-local struct — gets a different
//! validation hash on a runtime that composes those differently, and subxt then
//! refuses the read with `Metadata(IncompatibleCodegen)`. That is not a corruption
//! risk (subxt validates before decoding), but it makes the command unusable
//! against any runtime but the one the CLI shipped against.
//!
//! Reading such entries through [`subxt::dynamic`] decodes against the *live*
//! metadata instead. These helpers navigate the resulting [`Value`] by field and
//! variant *name*, so a command keeps working on any runtime that still calls the
//! fields what the pallet upstream calls them.

use crate::error::QuantusError;
use subxt::ext::scale_value::{Composite, Primitive, Value, ValueDef};

/// A dynamically decoded value, as produced by `DecodedValueThunk::to_value`.
pub(crate) type Val = Value<u32>;

/// The variant's name and its payload, or `None` if this is not an enum.
pub(crate) fn variant(v: &Val) -> Option<(&str, &Composite<u32>)> {
	match &v.value {
		ValueDef::Variant(var) => Some((var.name.as_str(), &var.values)),
		_ => None,
	}
}

/// The struct/tuple body, or `None` if this is not a composite.
pub(crate) fn composite(v: &Val) -> Option<&Composite<u32>> {
	match &v.value {
		ValueDef::Composite(c) => Some(c),
		_ => None,
	}
}

/// Look a field up by name. Unnamed composites have no named fields.
pub(crate) fn field<'a>(c: &'a Composite<u32>, name: &str) -> Option<&'a Val> {
	match c {
		Composite::Named(fields) => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
		Composite::Unnamed(_) => None,
	}
}

/// Positional access, for tuple variants such as `Ongoing(status)`.
pub(crate) fn nth(c: &Composite<u32>, i: usize) -> Option<&Val> {
	match c {
		Composite::Named(fields) => fields.get(i).map(|(_, v)| v),
		Composite::Unnamed(fields) => fields.get(i),
	}
}

/// Any unsigned integer, transparently unwrapping single-field newtypes.
pub(crate) fn uint(v: &Val) -> Option<u128> {
	match &v.value {
		ValueDef::Primitive(Primitive::U128(n)) => Some(*n),
		ValueDef::Composite(c) => nth(c, 0).and_then(uint),
		_ => None,
	}
}

/// One byte, read strictly. Unlike [`uint`] this does not reach into composites: a
/// `Vec<AccountId32>` must not pass as a byte string by yielding each account's first byte.
pub(crate) fn byte(v: &Val) -> Option<u8> {
	match &v.value {
		ValueDef::Primitive(Primitive::U128(n)) => u8::try_from(*n).ok(),
		_ => None,
	}
}

pub(crate) fn boolean(v: &Val) -> Option<bool> {
	match &v.value {
		ValueDef::Primitive(Primitive::Bool(b)) => Some(*b),
		_ => None,
	}
}

/// `Some(Some(inner))` / `Some(None)`, or `None` if the value is not an `Option`.
pub(crate) fn option(v: &Val) -> Option<Option<&Val>> {
	let (name, inner) = variant(v)?;
	match name {
		"None" => Some(None),
		"Some" => Some(Some(nth(inner, 0)?)),
		_ => None,
	}
}

/// A uniform error for a field the live runtime does not expose as expected.
pub(crate) fn missing(what: &str) -> QuantusError {
	QuantusError::Generic(format!(
		"decode: {what} is missing or has an unexpected shape; this runtime's pallet layout is \
		 not recognized"
	))
}

/// Read a named field as a `u32`.
pub(crate) fn u32_field(c: &Composite<u32>, name: &str) -> Result<u32, QuantusError> {
	let raw = field(c, name).and_then(uint).ok_or_else(|| missing(name))?;
	u32::try_from(raw).map_err(|_| missing(name))
}
