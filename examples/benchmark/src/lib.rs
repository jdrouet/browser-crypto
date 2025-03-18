mod bench;
mod helper;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PureCipher(aes_gcm::Aes256Gcm);

#[wasm_bindgen]
impl PureCipher {
    #[wasm_bindgen(js_name = "fromKey")]
    pub fn from_key(input: &[u8]) -> Result<Self, JsError> {
        use aes_gcm::KeyInit;

        aes_gcm::Aes256Gcm::new_from_slice(input)
            .map(Self)
            .map_err(|_| JsError::new("invalid cipher key"))
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, JsError> {
        use aes_gcm::aead::{Aead, OsRng};
        use aes_gcm::AeadCore;

        // Each encryption gets its own 96-bit nonce
        let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .0
            .encrypt(&nonce, input)
            .map_err(|_| JsError::new("unable to encrypt payload"))?;
        // We pack the nonce with the encrypted data
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, JsError> {
        use aes_gcm::aead::consts::U12;
        use aes_gcm::aead::Aead;

        // First 12 bytes are our nonce
        let Some((nonce, payload)) = input.split_at_checked(12) else {
            return Err(JsError::new("unable to extract nonce"));
        };

        let nonce = aes_gcm::Nonce::<U12>::from_slice(nonce);
        self.0
            .decrypt(nonce, payload)
            .map_err(|_| JsError::new("unable to decrypt payload"))
    }
}

#[wasm_bindgen]
pub struct WebCipher(browser_crypto::aes256gcm::Aes256Gcm);

#[wasm_bindgen]
impl WebCipher {
    #[wasm_bindgen(js_name = "fromKey")]
    pub async fn from_key(input: &[u8]) -> Result<Self, JsError> {
        let cipher = browser_crypto::aes256gcm::Aes256Gcm::from_key(&input).await?;
        Ok(Self(cipher))
    }

    #[wasm_bindgen]
    pub async fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, JsError> {
        use browser_crypto::algorithm::Algorithm;

        // Each encryption gets its own 96-bit nonce
        let nonce = browser_crypto::aes256gcm::Aes256Gcm::generate_nonce()
            .map_err(|_| JsError::new("unable to generate nonce"))?;
        let ciphertext = self
            .0
            .encrypt(&nonce, input)
            .await
            .map_err(|_| JsError::new("unable to encrypt payload"))?;

        // We pack the nonce with the encrypted data
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    #[wasm_bindgen]
    pub async fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, JsError> {
        use browser_crypto::algorithm::{Algorithm, Nonce};

        // First 12 bytes are our nonce
        let Some((nonce, payload)) = input.split_at_checked(12) else {
            return Err(JsError::new("unable to extract nonce"));
        };

        let nonce = Nonce::from_slice(nonce).map_err(|_| JsError::new("unable to parse nonce"))?;

        self.0
            .decrypt(&nonce, payload)
            .await
            .map_err(|_| JsError::new("unable to decrypt payload"))
    }
}
