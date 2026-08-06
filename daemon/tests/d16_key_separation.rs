//! D16 — key separation: the daemon holds ONLY the operator key, and only via the
//! environment. The withdrawal key has no representation anywhere in daemon config
//! or state, and a config that tries to smuggle key material in is rejected, not
//! silently ignored.

use blobsitter_daemon::config::{Config, ConfigError, OPERATOR_KEY_ENV};

fn write_config(dir: &std::path::Path, provider_section: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
instance = "0x0000000000000000000000000000000000000001"
execution_rpc = "http://127.0.0.1:1"
data_dir = "/tmp/nowhere"
deployment_block = 0

[beacon]
endpoints = ["http://127.0.0.1:1"]
genesis_time = 0

{provider_section}
"#
        ),
    )
    .unwrap();
    path
}

#[test]
fn d16_withdrawal_key_has_no_config_representation() {
    let dir = tempfile::tempdir().unwrap();
    // Neither a withdrawal address nor inline key material may parse: the schema
    // rejects unknown fields rather than carrying them silently.
    for contraband in
        ["withdrawal = \"0x1111111111111111111111111111111111111111\"", "operator_key = \"0xdead\""]
    {
        let path = write_config(dir.path(), &format!("[provider]\nid = 1\n{contraband}"));
        assert!(
            matches!(Config::load(&path), Err(ConfigError::Parse(_))),
            "config field '{contraband}' must be rejected"
        );
    }
}

#[test]
fn d16_operator_key_comes_from_the_environment_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "[provider]\nid = 1");
    let config = Config::load(&path).unwrap();
    let provider = config.provider.expect("provider section parsed");

    std::env::remove_var(OPERATOR_KEY_ENV);
    match provider.operator_key() {
        Err(ConfigError::MissingEnv(var)) => assert_eq!(var, OPERATOR_KEY_ENV),
        other => panic!("expected MissingEnv, got {other:?}"),
    }

    std::env::set_var(
        OPERATOR_KEY_ENV,
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    let key = provider.operator_key().expect("valid key loads");
    assert_eq!(
        key.address().to_string().to_lowercase(),
        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    );
    std::env::remove_var(OPERATOR_KEY_ENV);
}

/// Archive-only mode: no [provider] section means no duties and no key lookup at all.
#[test]
fn d16_archive_only_config_needs_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "");
    let config = Config::load(&path).unwrap();
    assert!(config.provider.is_none());
}
