//! Phase 4.6 verification: drive `tegmentum:key-backend.key.sign`
//! through the full Layer-3 stack (pkcs11-bridge + pkcs11-provider +
//! softhsm2.component) and verify the returned signature against the
//! returned SPKI using openssl-rs.
//!
//! Usage:
//!
//!   bash harness/run.sh
//!
//! Or directly:
//!
//!   cargo run --release -- \
//!     /tmp/full-pkcs11-stack.wasm \
//!     harness/softhsm2-wasi.conf \
//!     pkcs11:slot-id=0\;object=demo\;pin-value=1234
//!
//! Expects SoftHSM has been initialized via
//! `~/git/softhsm-wasm/scripts/softhsm-setup.sh` (which creates the
//! token directory + writes the demo key).

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use wasmtime::component::{Component, Linker, ResourceAny};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{
    DirPerms, FilePerms, ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
};

wasmtime::component::bindgen!({
    path: "wit",
    world: "harness",
    with: {
        "pkcs11:util/util/pin-provider": HostPin,
    },
});

use exports::tegmentum::key_backend::key_backend as kb;

struct State {
    table: ResourceTable,
    ctx: WasiCtx,
}
impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}

/// Inline PINs only -- the host pin-provider is never constructed.
pub struct HostPin;
impl pkcs11::util::util::Host for State {}
impl pkcs11::util::util::HostPinProvider for State {
    fn request_secret(
        &mut self,
        _self_: wasmtime::component::Resource<HostPin>,
        _label: Option<String>,
        _attempts_remaining: Option<u8>,
    ) -> Vec<u8> { Vec::new() }
    fn clear(&mut self, _: wasmtime::component::Resource<HostPin>) {}
    fn drop(&mut self, _: wasmtime::component::Resource<HostPin>) -> wasmtime::Result<()> {
        Ok(())
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let component_path = args.next().map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/full-pkcs11-stack.wasm"));
    let conf_path = args.next().map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("harness/softhsm2-wasi.conf"));
    let uri = args.next().unwrap_or_else(||
        "pkcs11:slot-id=0;object=demo-rsa;pin-value=1234".to_string());

    // Set up the WASI directory layout softhsm2 expects: /config/
    // (read-only conf) and /data/tokens/ (read-write token storage).
    let run = std::env::temp_dir()
        .join(format!("pkcs11-bridge-harness-{}", std::process::id()));
    let cfg_dir  = run.join("config");
    let data_dir = run.join("data");
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(data_dir.join("tokens"))?;
    let conf = std::fs::read(&conf_path)
        .with_context(|| format!("reading softhsm conf at {}", conf_path.display()))?;
    std::fs::write(cfg_dir.join("softhsm2-wasi.conf"), conf)?;

    let mut engine_cfg = Config::new();
    engine_cfg.wasm_component_model(true);
    let engine = Engine::new(&engine_cfg)?;
    let component = Component::from_file(&engine, &component_path)
        .with_context(|| format!("loading composed component {}", component_path.display()))?;

    let guest_stderr = MemoryOutputPipe::new(4 << 20);
    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdin()
        .inherit_stdout()
        .stderr(guest_stderr.clone())
        .env("SOFTHSM2_CONF", "/config/softhsm2-wasi.conf")
        .preopened_dir(&cfg_dir,  "/config", DirPerms::READ, FilePerms::READ)?
        .preopened_dir(&data_dir, "/data",   DirPerms::all(), FilePerms::all())?;
    let state = State {
        table: ResourceTable::new(),
        ctx: wasi.build(),
    };

    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    pkcs11::util::util::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker, |s| s,
    )?;
    let mut store = Store::new(&engine, state);
    let bindings = Harness::instantiate(&mut store, &component, &linker)?;
    let backend = bindings.tegmentum_key_backend_key_backend();

    let result = (|| -> Result<()> {
        println!("[1] key.new({uri:?})");
        let key: ResourceAny = backend.key().call_constructor(&mut store, &uri)
            .map_err(|t| anyhow!("trap during key.new: {t}"))?;

        println!("[2] key.algorithm()");
        let algo = backend.key().call_algorithm(&mut store, key)?;
        println!("    algorithm = {algo:?}");

        println!("[3] key.public-key-info()");
        let spki = backend.key().call_public_key_info(&mut store, key)
            .map_err(|t| anyhow!("trap: {t}"))?
            .map_err(|e: kb::BackendError| anyhow!("public_key_info: {e:?}"))?;
        println!("    SPKI = {} bytes", spki.len());

        println!("[4] key.sign(message, ECDSA-SHA256 or RSA-PKCS1-SHA256)");
        let message = b"phase-4 pkcs11-bridge end-to-end smoke".to_vec();
        let mech = match &algo {
            kb::KeyAlgorithm::Ec(_)  => kb::SignatureMechanism::Ecdsa(kb::DigestAlgorithm::Sha256),
            kb::KeyAlgorithm::Rsa(_) => kb::SignatureMechanism::RsaPkcs1(kb::DigestAlgorithm::Sha256),
            other => bail!("unexpected algorithm: {other:?}"),
        };
        let signature = backend.key().call_sign(&mut store, key, &message, mech)
            .map_err(|t| anyhow!("trap: {t}"))?
            .map_err(|e: kb::BackendError| anyhow!("sign: {e:?}"))?;
        println!("    signature = {} bytes", signature.len());

        println!("[5] verify with openssl-rs against the returned SPKI");
        let pubkey = openssl::pkey::PKey::public_key_from_der(&spki)
            .context("SPKI parse")?;
        let mut verifier = openssl::sign::Verifier::new(
            openssl::hash::MessageDigest::sha256(), &pubkey)
            .context("verifier")?;
        verifier.update(&message)?;
        let ok = verifier.verify(&signature).context("verify")?;
        if !ok {
            bail!("signature did NOT verify under the returned SPKI -- \
                   pkcs11-bridge mech mapping or SPKI assembly is wrong");
        }
        println!("\nOK -- pkcs11-bridge signed via SoftHSM in-sandbox; signature verifies natively.");
        Ok(())
    })();

    let logs = guest_stderr.contents();
    if !logs.is_empty() {
        eprintln!("\n--- guest stderr ---");
        eprint!("{}", String::from_utf8_lossy(&logs));
        eprintln!("--- end guest stderr ---");
    }
    result
}
