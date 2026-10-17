use std::{fs, process::Command};

use duck_rkp::{
    cbor::{as_array, decode, encode},
    cose::{DeviceKeys, build_experimental_csr_v3},
    profile::DeviceInfo,
};
use serde_json::{Value, json};

fn command(root: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckd"));
    command
        .env("DUCK_TOOLBOX_ROOT", root)
        .env("DUCK_TOOLBOX_DATA_ROOT", root);
    command
}

#[test]
fn cli_import_validates_and_diagnoses_without_csr_or_saved_profile() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("bin")).unwrap();
    fs::write(root.join("module.prop"), "id=duck-toolbox\n").unwrap();
    let signer = DeviceKeys::from_seed([0x71; 32]);
    let csr = build_experimental_csr_v3(&signer, &[], &[], &DeviceInfo::default()).unwrap();
    let value = decode(&csr).unwrap();
    let chain = encode(&as_array(&value, "fixture").unwrap()[2]).unwrap();
    fs::write(
        root.join("material.json"),
        serde_json::to_vec(&json!({
            "version":1, "dice_chain_hex":hex_string(&chain),
            "signing":{"kind":"ed25519-seed","bytes_hex":"71".repeat(32)},
            "device":DeviceInfo::default(),
        }))
        .unwrap(),
    )
    .unwrap();
    for (operation, stage) in [("validate", "validated"), ("diagnose", "diagnostic")] {
        let output = command(root)
            .args(["rkp", "import", operation, "--bundle", "material.json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["data"]["stage"], stage);
        assert_eq!(result["data"]["material"]["key_matches"], true);
        assert!(!result.to_string().contains(&"71".repeat(32)));
        if operation == "diagnose" {
            assert_eq!(result["data"]["diagnostic_only"], true);
            assert!(std::path::Path::new(result["data"]["csr_path"].as_str().unwrap()).is_file());
        } else {
            assert_eq!(result["data"]["ready_for_issuance"], false);
        }
    }
    let output = command(root)
        .args(["rkp", "import", "issue", "--bundle", "material.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root.join("var/profile.toml").exists());
    let log = fs::read_to_string(root.join("var/logs/duckd.log")).unwrap();
    assert!(!log.contains(&"71".repeat(32)));
}

#[test]
fn cli_import_rejects_missing_and_conflicting_inputs_with_failure_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("bin")).unwrap();
    fs::write(root.join("module.prop"), "id=duck-toolbox\n").unwrap();
    for args in [
        vec!["rkp", "import", "validate"],
        vec!["rkp", "import", "validate", "--bundle", "missing.json"],
    ] {
        let output = command(root).args(args).output().unwrap();
        assert!(!output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["code"], "material_structure");
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
