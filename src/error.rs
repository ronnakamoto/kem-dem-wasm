use wasm_bindgen::prelude::*;

/// Errors are surfaced as JS exceptions.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct CryptoError {
    message: String,
}

#[wasm_bindgen]
impl CryptoError {
    #[wasm_bindgen(constructor)]
    pub fn new(message: String) -> Self {
        Self { message }
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CryptoError {}

impl From<serde_wasm_bindgen::Error> for CryptoError {
    fn from(err: serde_wasm_bindgen::Error) -> Self {
        Self::new(format!("Serialization failed: {err}"))
    }
}

impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::new("Invalid key or ciphertext length".to_string())
    }
}

impl From<hpke::HpkeError> for CryptoError {
    fn from(err: hpke::HpkeError) -> Self {
        Self::new(format!("HPKE operation failed: {err}"))
    }
}

/// Convert CryptoError to JsValue manually without implementing From trait
/// to avoid conflict with wasm-bindgen auto-generated impl.
pub fn to_js_value(err: CryptoError) -> JsValue {
    JsValue::from(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_error_new_and_message() {
        let err = CryptoError::new("test error".to_string());
        assert_eq!(err.message(), "test error");
    }

    #[test]
    fn crypto_error_display() {
        let err = CryptoError::new("display test".to_string());
        assert_eq!(format!("{err}"), "display test");
    }

    #[test]
    fn crypto_error_from_try_from_slice_error() {
        let slice: &[u8] = &[1, 2, 3];
        let result = <&[u8; 32]>::try_from(slice);
        let err: CryptoError = result.unwrap_err().into();
        assert_eq!(err.message(), "Invalid key or ciphertext length");
    }

    #[test]
    fn crypto_error_from_hpke_error() {
        let err = CryptoError::from(hpke::HpkeError::ValidationError);
        assert_eq!(
            err.message(),
            "HPKE operation failed: Input value is invalid"
        );
    }

    #[test]
    fn crypto_error_clone_and_debug() {
        let err = CryptoError::new("clone me".to_string());
        let cloned = err.clone();
        assert_eq!(cloned.message(), "clone me");
        assert!(format!("{:?}", cloned).contains("clone me"));
    }
}
