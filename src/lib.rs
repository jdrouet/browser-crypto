use js_sys::Promise;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, WorkerGlobalScope};

pub mod aes256gcm;
pub mod algorithm;

async fn resolve<V, E: From<JsValue> + From<Error>>(promise: Promise) -> Result<V, E>
where
    V: JsCast,
    E: From<JsValue>,
{
    JsFuture::from(promise)
        .await
        .and_then(|value| value.dyn_into::<V>())
        .map_err(E::from)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("unable to read global scope")]
    GlobalScopeNotFound,
    #[error("unable to access crypto interface")]
    CryptoUnreachable,
    #[error("DOMException {0}: {1}")]
    DomException(String, String),
    #[error("unknown exception")]
    Unknown,
}

impl From<JsValue> for Error {
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            Self::DomException(exception.name(), exception.message())
        } else {
            #[cfg(feature = "log-error")]
            web_sys::console::error_1(&value);
            Self::Unknown
        }
    }
}

fn scope() -> Result<web_sys::WorkerGlobalScope, Error> {
    js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| Error::GlobalScopeNotFound)
}

fn crypto() -> Result<web_sys::Crypto, Error> {
    scope().and_then(|scope| scope.crypto().map_err(|_| Error::CryptoUnreachable))
}

fn subtle() -> Result<web_sys::SubtleCrypto, Error> {
    crypto().map(|crypto| crypto.subtle())
}

fn array_to_vec(input: &js_sys::Uint8Array) -> Vec<u8> {
    let mut output = vec![0; input.length() as usize];
    input.copy_to(&mut output);
    output
}
