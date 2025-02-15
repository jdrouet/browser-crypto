//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use browser_crypto::algorithm::Algorithm;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

pub const DEFAULT_KEY: [u8; 32] = [42; 32];

#[wasm_bindgen_test]
async fn should_have_the_same_encrypted_output() {
    // in this test, we use empty nonces
    console_error_panic_hook::set_once();

    let clear_msg = b"Hello World!";
    let browser = browser_crypto::aes256gcm::Aes256Gcm::from_key(&DEFAULT_KEY)
        .await
        .unwrap();
    let browser_nonce = browser_crypto::algorithm::Nonce::from_slice(&[0; 12]).unwrap();
    let browser_encrypted = browser.encrypt(&browser_nonce, clear_msg).await.unwrap();

    let pure = aes_gcm::Aes256Gcm::new_from_slice(&DEFAULT_KEY).unwrap();
    let pure_nonce = aes_gcm::Nonce::default();
    let pure_encrypted = pure.encrypt(&pure_nonce, clear_msg.as_ref()).unwrap();

    assert_eq!(browser_encrypted, pure_encrypted);
}

#[wasm_bindgen_test]
async fn pure_should_decrypt_webcrypto() {
    console_error_panic_hook::set_once();

    let clear_msg = b"Hello World!";
    let browser = browser_crypto::aes256gcm::Aes256Gcm::from_key(&DEFAULT_KEY)
        .await
        .unwrap();
    let browser_nonce = browser_crypto::aes256gcm::Aes256Gcm::generate_nonce().unwrap();
    let encrypted = browser.encrypt(&browser_nonce, clear_msg).await.unwrap();

    let pure = aes_gcm::Aes256Gcm::new_from_slice(&DEFAULT_KEY).unwrap();
    let pure_nonce = browser_nonce.to_vec();
    let pure_nonce = aes_gcm::Nonce::from_slice(&pure_nonce);
    let decrypted = pure.decrypt(&pure_nonce, encrypted.as_ref()).unwrap();

    assert_eq!(decrypted, clear_msg);
}

#[wasm_bindgen_test]
async fn webcrypto_should_decrypt_pure() {
    console_error_panic_hook::set_once();

    let clear_msg = b"Hello World!";

    let browser_nonce = browser_crypto::aes256gcm::Aes256Gcm::generate_nonce().unwrap();

    let pure = aes_gcm::Aes256Gcm::new_from_slice(&DEFAULT_KEY).unwrap();
    let pure_nonce = browser_nonce.to_vec();
    let pure_nonce = aes_gcm::Nonce::from_slice(&pure_nonce);
    let encrypted = pure.encrypt(&pure_nonce, clear_msg.as_ref()).unwrap();

    let browser = browser_crypto::aes256gcm::Aes256Gcm::from_key(&DEFAULT_KEY)
        .await
        .unwrap();
    let decrypted = browser
        .decrypt(&browser_nonce, encrypted.as_ref())
        .await
        .unwrap();

    assert_eq!(decrypted, clear_msg);
}
