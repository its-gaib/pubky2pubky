use wasm_bindgen::JsValue;

pub(crate) type BrowserResult<T> = Result<T, JsValue>;

pub(crate) fn failure(code: &'static str) -> JsValue {
    js_sys::Error::new(code).into()
}

pub(crate) fn opaque_failure(_error: impl std::fmt::Display) -> JsValue {
    failure("internal-error")
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership of the JavaScript rejection value"
)]
pub(crate) fn storage_failure(value: JsValue) -> JsValue {
    const ALLOWED: &[&str] = &[
        "browser-unsupported",
        "device-state-exists",
        "ed25519-unsupported",
        "grant-key-missing",
        "identity-exists",
        "identity-not-found",
        "invalid-pubky",
        "publisher-already-initialized",
        "publisher-state-missing",
        "sequence-batch-conflict",
        "sequence-digest-required",
        "sequence-equivocation",
        "sequence-invalid",
        "sequence-limit",
        "sequence-rollback",
        "signing-failed",
        "signing-input-invalid",
        "storage-blocked",
        "storage-failed",
        "storage-invalid",
        "storage-key-missing",
        "storage-tampered",
        "storage-too-large",
    ];
    let message = value.as_string().or_else(|| {
        js_sys::Reflect::get(&value, &JsValue::from_str("message"))
            .ok()
            .and_then(|message| message.as_string())
    });
    match message.as_deref() {
        Some(code) if ALLOWED.contains(&code) => js_sys::Error::new(code).into(),
        _ => failure("storage-failed"),
    }
}
