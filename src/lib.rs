use js_sys::Promise;
use std::io::{Error, ErrorKind, Result};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, Exception, WorkerGlobalScope};

pub mod aes256gcm;
pub mod algorithm;

fn from_js<V: JsCast>(value: JsValue) -> Result<V> {
    value.dyn_into::<V>().map_err(from_js_error)
}

fn from_js_error(value: JsValue) -> Error {
    if value.is_instance_of::<DomException>() {
        let handle = value.unchecked_into::<DomException>();
        return Error::other(handle.name());
    }
    if value.is_instance_of::<Exception>() {
        let handle = value.unchecked_into::<Exception>();
        return Error::other(handle.name());
    }
    if let Some(err) = value.dyn_ref::<web_sys::js_sys::TypeError>() {
        let message: String = err.message().into();
        return Error::new(ErrorKind::InvalidInput, message);
    }
    Error::other("unknown error")
}

async fn resolve<V: JsCast>(promise: Promise) -> Result<V> {
    from_js(JsFuture::from(promise).await.map_err(from_js_error)?)
}

fn scope() -> Result<web_sys::WorkerGlobalScope> {
    js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| Error::other("unable to read scope"))
}

fn crypto() -> Result<web_sys::Crypto> {
    scope().and_then(|scope| scope.crypto().map_err(from_js_error))
}

fn subtle() -> Result<web_sys::SubtleCrypto> {
    crypto().map(|crypto| crypto.subtle())
}

fn array_to_vec(input: &js_sys::Uint8Array) -> Vec<u8> {
    let mut output = vec![0; input.length() as usize];
    input.copy_to(&mut output);
    output
}
