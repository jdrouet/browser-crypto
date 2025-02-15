//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use std::assert_eq;

use browser_crypto::algorithm::Algorithm;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

pub const DEFAULT_KEY: [u8; 32] = [42; 32];

#[wasm_bindgen_test]
async fn should_encrypt_and_decrypt() {
    console_error_panic_hook::set_once();

    let clear_msg = b"Hello World!";
    let crypto = browser_crypto::aes256gcm::Aes256Gcm::from_key(&DEFAULT_KEY)
        .await
        .unwrap();
    let nonce = browser_crypto::aes256gcm::Aes256Gcm::generate_nonce().unwrap();
    let encrypted = crypto.encrypt(&nonce, clear_msg).await.unwrap();

    let decrypted = crypto.decrypt(&nonce, &encrypted).await.unwrap();

    assert_eq!(clear_msg, decrypted.as_slice());
}

#[wasm_bindgen_test]
async fn should_handle_invalid_keys() {
    console_error_panic_hook::set_once();

    let err = browser_crypto::aes256gcm::Aes256Gcm::from_key(&[0; 30])
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "invalid key format provided");

    let err = browser_crypto::aes256gcm::Aes256Gcm::from_key(&[0; 40])
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "invalid key format provided");
}

#[wasm_bindgen_test]
async fn should_handle_invalid_nonce() {
    console_error_panic_hook::set_once();
    let clear_msg = b"Hello World!";
    let crypto = browser_crypto::aes256gcm::Aes256Gcm::from_key(&DEFAULT_KEY)
        .await
        .unwrap();
    let err = browser_crypto::algorithm::Nonce::<browser_crypto::aes256gcm::Aes256Gcm>::from_slice(
        &[0; 10],
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid nonce size provided, expected 12, received 10"
    );
}
