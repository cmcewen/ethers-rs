extern crate libc;

// use the ethers_signers crate to manage LocalWallet and Signer
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_signers::{coins_bip39::English, LocalWallet, MnemonicBuilder};

use libc::c_char;
use std::ffi::CStr;
use std::ffi::CString;

#[no_mangle]
pub extern "C" fn wallet_from_mnemonic_new(
  mnemonic: *const c_char,
  index: u32,
) -> *mut LocalWallet {
  let mnemonic_c_str = unsafe {
    assert!(!mnemonic.is_null());

    CStr::from_ptr(mnemonic)
  };
  let mnemonic_str = mnemonic_c_str.to_str().unwrap();

  let wallet: LocalWallet = MnemonicBuilder::<English>::default()
    .phrase(mnemonic_str)
    .index(index)
    .unwrap()
    .build()
    .unwrap();

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
pub extern "C" fn signed_tx_free(sig: *mut c_char) {
  unsafe {
    if sig.is_null() {
      return;
    }
    CString::from_raw(sig)
  };
}
