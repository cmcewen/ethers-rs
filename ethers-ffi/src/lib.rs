extern crate libc;

// use the ethers_signers crate to manage LocalWallet and Signer
use coins_bip32::{path::DerivationPath, enc::{XKeyEncoder, MainnetEncoder}};
use coins_bip39::{English, Mnemonic};
use ethers_core::types::{transaction::eip2718::TypedTransaction, Address};
use ethers_core::utils::keccak256;
use ethers_signers::LocalWallet;
use k256::ecdsa::{VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use libc::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::str::FromStr;
use ffi_convert::*;

const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";

// copied from aws/utils
/// Convert a verifying key to an ethereum address
fn verifying_key_to_address(key: VerifyingKey) -> Address {
  // false for uncompressed
  let uncompressed_pub_key = key.to_encoded_point(false);
  let public_key = uncompressed_pub_key.to_bytes();
  debug_assert_eq!(public_key[0], 0x04);
  let hash = keccak256(&public_key[1..]);
  Address::from_slice(&hash[12..])
}

pub struct PrivateKey {
  private_key: String,
  address: String,
}

#[repr(C)]
#[derive(CReprOf, AsRust, CDrop)]
#[target_type(PrivateKey)]
pub struct CPrivateKey {
  private_key: *const c_char,
  address: *const c_char,
}

#[no_mangle]
pub extern "C" fn generate_mnemonic() -> *mut c_char {
  let rng = &mut rand::thread_rng();
  let mnemonic = Mnemonic::<English>::new_with_count(rng, 12)
    .unwrap()
    .to_phrase()
    .unwrap();
  let mnemonic_c_str = CString::new(mnemonic).unwrap();
  return mnemonic_c_str.into_raw();
}

#[no_mangle]
pub extern "C" fn private_key_from_mnemonic(
  mnemonic_cstr: *const c_char,
  index: u32,
) -> CPrivateKey {
  let mnemonic_str = cstr_to_string(&mnemonic_cstr);
  let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic_str).unwrap();
  let derivation_path = DerivationPath::from_str(&format!(
    "{}{}",
    DEFAULT_DERIVATION_PATH_PREFIX,
    index.to_string()
  ))
  .unwrap();
  let private_key = mnemonic.derive_key(derivation_path, None).unwrap();
  let private_key_str = MainnetEncoder::xpriv_to_base58(&private_key).unwrap();
  let verifying_key = private_key.verify_key();
  let address = verifying_key_to_address(verifying_key.key);
  let address_str_json = serde_json::to_string_pretty(&address).unwrap();
  let address_str = format!("{}", address_str_json.replace("\"", ""));

  let priv_struct = PrivateKey {
    private_key: private_key_str,
    address: address_str,
  };

  return CPrivateKey::c_repr_of(priv_struct).unwrap();
}

#[no_mangle]
pub extern "C" fn private_key_free(private_key: CPrivateKey) {
  drop(private_key);
}

#[no_mangle]
pub extern "C" fn wallet_from_private_key(private_key: *const c_char) -> *mut LocalWallet {
  let key_str = cstr_to_string(&private_key);
  let xpriv = MainnetEncoder::xpriv_from_base58(key_str).unwrap();
  let wallet = LocalWallet::from(xpriv.key);
  return opaque_pointer::raw(wallet);
}

#[no_mangle]
pub extern "C" fn wallet_free(wallet_ptr: *mut LocalWallet) {
  unsafe { opaque_pointer::own_back(wallet_ptr) }.unwrap();
}

#[no_mangle]
pub extern "C" fn sign_tx_with_wallet(
  wallet_ptr: *const LocalWallet,
  json_tx: *const c_char,
) -> *mut c_char {
  let wallet = unsafe { opaque_pointer::object(wallet_ptr) }.unwrap();
  let tx_c_str = unsafe {
    assert!(!json_tx.is_null());

    CStr::from_ptr(json_tx)
  };
  let tx_str = tx_c_str.to_str().unwrap();
  let tx: TypedTransaction = serde_json::from_str(tx_str).unwrap();

  let signature = wallet.sign_transaction_sync(&tx);

  let sig_string = serde_json::to_string(&signature).unwrap();
  let sig_c_str = CString::new(sig_string).unwrap();
  return sig_c_str.into_raw();
}

#[no_mangle]
pub extern "C" fn string_free(string: *mut c_char) {
  unsafe {
    if string.is_null() {
      return;
    }
    CString::from_raw(string)
  };
}

fn cstr_to_string<'a>(cstr_ptr: &'a *const c_char) -> &'a str {
  let cstr = unsafe {
    assert!(!cstr_ptr.is_null());
    CStr::from_ptr(*cstr_ptr)
  };
  return cstr.to_str().unwrap();
}
