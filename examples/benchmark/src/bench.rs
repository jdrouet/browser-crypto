use getrandom::getrandom;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "createPayload")]
pub fn create_payload(size: usize) -> Result<Vec<u8>, JsError> {
    let mut payload = vec![0; size];
    getrandom(&mut payload).map_err(|_| JsError::new("unable to generate random"))?;
    Ok(payload)
}
