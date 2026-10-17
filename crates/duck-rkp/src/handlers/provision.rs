use duck_core::{AppPaths, Failure};
use serde::Serialize;

use super::{ensure_request_context, random_bytes, resolve_runtime};
use crate::{
    artifacts::{SavedKey, private_run, save_issued},
    cli::ProvisionArgs,
    cose::{DeviceKeys, build_experimental_csr_v3, generate_ec_keypair},
    crypto_kdf::resolve_seed,
    private_output::write_new_verified,
    verify::VerifyReport,
    workflow::{issue, validate_request_binding},
};

#[derive(Serialize)]
pub(crate) struct ProvisionData {
    mode: &'static str,
    curve: String,
    challenge_hex: String,
    csr_path: String,
    csr_len: usize,
    protected_data_len: usize,
    local_verify: VerifyReport,
    cert_chains: Vec<SavedKey>,
    local_test_mode: bool,
    diagnostic_only: bool,
    fetch_eek_error: Option<String>,
    server_submission_error: Option<String>,
}

pub(crate) async fn run(paths: &AppPaths, args: &ProvisionArgs) -> Result<ProvisionData, Failure> {
    let resolved = resolve_runtime(paths, &args.shared, args.num_keys, None)?;
    let server_url = ensure_request_context(&resolved.profile)?;
    let keys = DeviceKeys::from_seed_with_curve(
        resolve_seed(&resolved.profile.key_source)?,
        resolved.profile.curve,
    );
    let build = |challenge: &[u8], public: &[ciborium::value::Value]| {
        build_experimental_csr_v3(&keys, challenge, public, &resolved.profile.device)
    };
    let (csr, challenge, report, saved_keys, csr_path) = if args.offline {
        let challenge = random_bytes(32)?;
        let key = generate_ec_keypair()?;
        let public = [key.cose_public];
        let csr = build(&challenge, &public)?;
        let report = validate_request_binding(&csr, &challenge, &public)?;
        let directory = private_run(paths, "rkp-experimental-diagnostic-")?;
        let path = directory.path().join("diagnostic-only.cbor");
        write_new_verified(&path, &csr, |bytes| {
            validate_request_binding(bytes, &challenge, &public).map(|_| ())
        })?;
        let _ = directory.keep();
        (
            csr,
            challenge,
            report,
            Vec::new(),
            path.display().to_string(),
        )
    } else {
        let issued = issue(
            &resolved.profile.fingerprint.value,
            &server_url,
            resolved.profile.num_keys,
            build,
        )
        .await?;
        let saved = save_issued(paths, &issued, "rkp-experimental-", None)?;
        (
            issued.csr,
            issued.challenge,
            issued.report,
            saved.keys,
            saved.csr_path,
        )
    };
    Ok(ProvisionData {
        mode: "experimental",
        curve: resolved.profile.curve.as_str().into(),
        challenge_hex: hex::encode(challenge),
        csr_len: csr.len(),
        csr_path,
        protected_data_len: 0,
        local_verify: report,
        cert_chains: saved_keys,
        local_test_mode: args.offline,
        diagnostic_only: args.offline,
        fetch_eek_error: None,
        server_submission_error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::SharedRunArgs,
        profile::{KeySource, ProfileData, save_profile},
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    #[tokio::test]
    async fn challenge_failure_is_an_error_without_submission_or_artifacts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).contains(":fetchEekChain"));
            socket
                .write_all(
                    b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::for_root(dir.path(), dir.path());
        let profile = ProfileData {
            key_source: KeySource::Seed {
                seed_hex: "11".repeat(32),
            },
            server_url: format!("http://{address}/v1"),
            ..ProfileData::default()
        };
        save_profile(&paths, None, &profile).unwrap();
        let result = run(
            &paths,
            &ProvisionArgs {
                shared: SharedRunArgs::default(),
                num_keys: None,
                offline: false,
            },
        )
        .await;
        worker.join().unwrap();
        assert!(
            result.is_err(),
            "online failure must not be reported as a successful offline run"
        );
        assert_eq!(std::fs::read_dir(&paths.outputs_dir).unwrap().count(), 0);
    }
}
