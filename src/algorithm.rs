use std::{io::Result, marker::PhantomData};

#[derive(Debug, Clone)]
pub struct Nonce<A> {
    algo: PhantomData<A>,
    inner: js_sys::Uint8Array,
}

impl<A> AsRef<js_sys::Uint8Array> for Nonce<A> {
    fn as_ref(&self) -> &js_sys::Uint8Array {
        &self.inner
    }
}

impl<A> Nonce<A>
where
    A: Algorithm,
    A: Sized,
{
    pub fn generate() -> Result<Nonce<A>> {
        let crypto = crate::crypto()?;
        let inner = js_sys::Uint8Array::new_with_length(A::NONCE_SIZE);
        crypto
            .get_random_values_with_js_u8_array(&inner)
            .map_err(crate::from_js_error)?;
        Ok(Nonce {
            algo: PhantomData,
            inner,
        })
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            algo: PhantomData,
            inner: js_sys::Uint8Array::from(data),
        }
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = u8> + 'a {
        (0..self.inner.length()).map(|idx| self.inner.get_index(idx))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        crate::array_to_vec(&self.inner)
    }
}

pub trait Algorithm: Sized {
    const NONCE_SIZE: u32;

    fn generate_nonce() -> Result<Nonce<Self>> {
        Nonce::<Self>::generate()
    }

    fn encrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>>;

    fn decrypt(
        &self,
        nonce: &Nonce<Self>,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>>;
}
