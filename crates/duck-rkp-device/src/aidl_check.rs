use std::{
    fs,
    io::{Cursor, Read},
    os::unix::fs::PermissionsExt,
    process::Command,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use duck_core::Context as AppContext;
use duck_rkp::{
    cbor::{as_array, as_bytes},
    verify::verify_csr,
};
use serde::Serialize;

use crate::{
    error::DeviceRkpError,
    process,
    protocol::{BUFFER_SIZE, decode_exact},
    v1,
};

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const BRIDGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rkp-v1.jar"));
#[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
const BRIDGE: &[u8] = &[];

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    instance: String,
    hardware_version: i32,
    supported_eek_curve: i32,
    interface_version: Option<i32>,
    author: String,
    checks: [CsrCheck; 2],
    server_acceptance_checked: bool,
}

#[derive(Debug, Serialize)]
struct CsrCheck {
    challenge_bytes: usize,
    csr_bytes: usize,
    keys_to_sign: usize,
    signature_valid: bool,
    challenge_matches: bool,
}

pub(crate) fn parse_instance(value: &str) -> std::result::Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(
            "expected a 1..64 character instance name containing only letters, digits, _, . or -"
                .into(),
        );
    }
    Ok(value.into())
}

pub(crate) fn run(ctx: &AppContext, instance: &str) -> Result<Report> {
    parse_instance(instance).map_err(anyhow::Error::msg)?;
    if BRIDGE.is_empty() {
        return Err(
            DeviceRkpError::UnsupportedDevice("AIDL checks require Android arm64".into()).into(),
        );
    }
    let apk = v1::find_aidl_apk(&ctx.sysroot).ok_or_else(|| {
        DeviceRkpError::UnsupportedDevice("system RKP AIDL classes are unavailable".into())
    })?;
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).context("generate diagnostic challenge")?;
    fs::create_dir_all(&ctx.paths.tmp_dir)?;
    let exchange = tempfile::Builder::new()
        .prefix("rkp-aidl-check-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&ctx.paths.tmp_dir)?;
    let jar = exchange.path().join("bridge.jar");
    fs::write(&jar, BRIDGE)?;
    fs::set_permissions(&jar, fs::Permissions::from_mode(0o400))?;
    fs::write(exchange.path().join("request.bin"), challenge)?;
    let mut command = Command::new(v1::APP_PROCESS);
    command
        .env("CLASSPATH", format!("{}:{}", jar.display(), apk.display()))
        .args(["/system/bin", "duck.rkp.RkpV2Check"])
        .arg(exchange.path())
        .arg(instance);
    let status = process::run(&mut command, Duration::from_secs(30))?;
    if !status.success() {
        return Err(
            DeviceRkpError::Transport(format!("AIDL V2 check exited with {status}")).into(),
        );
    }
    let bytes =
        process::read_exchange_file(&exchange.path().join("reply.bin"), BUFFER_SIZE * 2 + 4096)?;
    decode_report(&bytes, instance, &challenge).map_err(|error| {
        if error.chain().any(|cause| cause.is::<DeviceRkpError>()) {
            error
        } else {
            DeviceRkpError::InvalidResponse(format!("AIDL V2 check: {error:#}")).into()
        }
    })
}

fn decode_report(bytes: &[u8], instance: &str, challenge: &[u8]) -> Result<Report> {
    let mut input = Cursor::new(bytes);
    let status = number(&mut input)?;
    if status != 0 {
        let code = if status == 1 {
            Some(number(&mut input)?)
        } else {
            None
        };
        if !(1..=4).contains(&status) {
            bail!("unknown AIDL check status {status}");
        }
        let message = text(&mut input)?;
        ensure_end(&input)?;
        let message = format!("AIDL V2 check: {message}");
        return Err(match code {
            Some(code) => anyhow::Error::new(DeviceRkpError::Rejected(code)).context(message),
            None => match status {
                2 => DeviceRkpError::Transport(message).into(),
                3 => DeviceRkpError::InvalidResponse(message).into(),
                _ => DeviceRkpError::UnsupportedProtocol(message).into(),
            },
        });
    }
    let hardware_version = number(&mut input)?;
    let supported_eek_curve = number(&mut input)?;
    let interface_version = number(&mut input)?;
    let author = text(&mut input)?;
    let _unique_id = text(&mut input)?;
    if hardware_version < 3 || interface_version < -1 {
        bail!("invalid AIDL capability reply");
    }
    let empty = field(&mut input, BUFFER_SIZE)?;
    let challenged = field(&mut input, BUFFER_SIZE)?;
    ensure_end(&input)?;
    Ok(Report {
        instance: instance.into(),
        hardware_version,
        supported_eek_curve,
        interface_version: (interface_version != -1).then_some(interface_version),
        author,
        checks: [
            validate_csr(&empty, &[])?,
            validate_csr(&challenged, challenge)?,
        ],
        server_acceptance_checked: false,
    })
}

fn validate_csr(csr: &[u8], challenge: &[u8]) -> Result<CsrCheck> {
    let validate = || -> Result<CsrCheck> {
        let report = verify_csr(csr)?;
        if !report.signature_valid || report.cert_type != "keymint" || report.keys_to_sign != 0 {
            bail!("expected a signed keymint CSR with no keysToSign");
        }
        let request = decode_exact(csr)?;
        let request = as_array(&request, "CSR")?;
        let signed = as_array(request.get(3).context("missing SignedData")?, "SignedData")?;
        let signed_payload = decode_exact(as_bytes(
            signed.get(2).context("missing signed payload")?,
            "signed payload",
        )?)?;
        let payload = as_array(&signed_payload, "signed payload")?;
        if as_bytes(payload.first().context("missing challenge")?, "challenge")? != challenge {
            bail!("CSR challenge does not match the diagnostic challenge");
        }
        Ok(CsrCheck {
            challenge_bytes: challenge.len(),
            csr_bytes: csr.len(),
            keys_to_sign: 0,
            signature_valid: true,
            challenge_matches: true,
        })
    };
    validate()
        .map_err(|error| DeviceRkpError::InvalidCsr(format!("AIDL V2 check: {error:#}")).into())
}

fn number(input: &mut Cursor<&[u8]>) -> Result<i32> {
    let mut bytes = [0; 4];
    input
        .read_exact(&mut bytes)
        .context("truncated AIDL check header")?;
    Ok(i32::from_be_bytes(bytes))
}

fn field(input: &mut Cursor<&[u8]>, max: usize) -> Result<Vec<u8>> {
    let length = number(input)?;
    if length < 0 || length as usize > max {
        bail!("invalid AIDL check field length");
    }
    let mut bytes = vec![0; length as usize];
    input
        .read_exact(&mut bytes)
        .context("truncated AIDL check field")?;
    Ok(bytes)
}

fn text(input: &mut Cursor<&[u8]>) -> Result<String> {
    Ok(String::from_utf8(field(input, 1024)?)?)
}

fn ensure_end(input: &Cursor<&[u8]>) -> Result<()> {
    if input.position() != input.get_ref().len() as u64 {
        bail!("trailing AIDL check reply data");
    }
    Ok(())
}

#[cfg(test)]
#[path = "aidl_check_tests.rs"]
mod tests;
