//! End to end pipeline tests: config -> pipeline -> alerts, offline mode,
//! denylist and unknown verdicts. No network access is used.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use sha2::Digest as _;
use unfamous::config::Config;
use unfamous::daemon::{FileContext, Pipeline};

fn temp_config(dir: &std::path::Path, denylist_sha256: Option<&str>) -> Config {
    let mut config = Config::default();
    config.general.hostname = "testhost".into();
    config.cache.database_path = dir.join("cache.db").display().to_string();
    config.alerts.directory = dir.join("alerts").display().to_string();
    config.hashing.algorithms = vec!["sha256".into(), "md5".into()];
    config.monitoring.enabled = false;
    config.general.offline = true;
    config.file_types.shell_scripts = true;
    config.providers.virustotal.enabled = true;
    config.providers.virustotal.api_key_env = Some("UNFAMOUS_VT_API_KEY".into());
    config.providers.circl_hashlookup.enabled = true;
    if let Some(hash) = denylist_sha256 {
        config.lists.denylist.sha256 = vec![hash.to_string()];
    }
    config
}

fn write_fixture(dir: &std::path::Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = fs::File::create(&path).expect("create fixture");
    file.write_all(content).expect("write fixture");
    path
}

async fn scan(pipeline: &Pipeline, path: &std::path::Path) -> Option<unfamous::alerts::Alert> {
    let outcome = pipeline
        .process(&FileContext {
            path: Some(path.to_path_buf()),
            fd: None,
            pid: None,
            mode: "scan",
            bypass_cache: false,
        })
        .await;
    outcome.expect("pipeline run").alert
}

#[tokio::test]
async fn unknown_script_generates_alert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(temp_config(dir.path(), None));
    let pipeline = Pipeline::build(config).expect("pipeline");
    let js = write_fixture(dir.path(), "dropper.js", b"var x = fetch('http://x');\n");
    let alert = scan(&pipeline, &js).await.expect("alert expected");
    assert_eq!(
        alert.reputation,
        unfamous::reputation::ReputationVerdict::Unknown
    );
    assert_eq!(alert.monitoring_mode, "scan");
    assert_eq!(alert.hostname, "testhost");
    assert_eq!(alert.file_extension.as_deref(), Some(".js"));
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"var x = fetch('http://x');\n");
    assert_eq!(
        alert.sha256.as_deref(),
        Some(hex::encode(hasher.finalize()).as_str())
    );
    assert!(alert.md5.is_some());

    let alert_dir = dir.path().join("alerts");
    let files: Vec<_> = fs::read_dir(&alert_dir).expect("alert dir").collect();
    assert_eq!(files.len(), 1, "one alert file");
    let content = fs::read_to_string(files[0].as_ref().expect("entry").path()).expect("read");
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).expect("valid json");
    assert_eq!(parsed["reputation"], "UNKNOWN");
}

#[tokio::test]
async fn denylisted_file_alerts_as_known_bad() {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = b"#!/bin/sh\nrm -rf /\n";
    let mut hasher = sha2::Sha256::new();
    hasher.update(content);
    let hash = hex::encode(hasher.finalize());
    let config = Arc::new(temp_config(dir.path(), Some(&hash)));
    let pipeline = Pipeline::build(config).expect("pipeline");
    let script = write_fixture(dir.path(), "wipe.sh", content);
    let alert = scan(&pipeline, &script).await.expect("alert expected");
    assert_eq!(
        alert.reputation,
        unfamous::reputation::ReputationVerdict::KnownBad
    );
    assert!(alert.detection_reason.contains("denylist"));
}

#[tokio::test]
async fn non_matching_files_are_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(temp_config(dir.path(), None));
    let pipeline = Pipeline::build(config).expect("pipeline");
    let png = write_fixture(dir.path(), "image.png", b"\x89PNG\r\n\x1a\n");
    assert!(scan(&pipeline, &png).await.is_none());
    let text = write_fixture(dir.path(), "notes.txt", b"plain text\n");
    assert!(scan(&pipeline, &text).await.is_none());
}

#[tokio::test]
async fn oversized_file_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = temp_config(dir.path(), None);
    config.hashing.max_file_size_mb = 0; // validates to >0 in real configs; bypass via direct struct
    let config = Arc::new(config);
    let pipeline = Pipeline::build(config).expect("pipeline");
    let big = write_fixture(dir.path(), "huge.js", &vec![b'a'; 4096]);
    assert!(scan(&pipeline, &big).await.is_none());
}

#[tokio::test]
async fn unreadable_file_does_not_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(temp_config(dir.path(), None));
    let pipeline = Pipeline::build(config).expect("pipeline");
    let js = write_fixture(dir.path(), "locked.js", b"var x = 1;\n");
    let mut perms = fs::metadata(&js).expect("meta").permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&js, perms).expect("chmod");
    if fs::read(&js).is_ok() {
        return; // running as root, permissions do not apply
    }
    let result = pipeline
        .process(&FileContext {
            path: Some(js.clone()),
            fd: None,
            pid: None,
            mode: "scan",
            bypass_cache: false,
        })
        .await;
    // The DFIR layer counts this as a per-file error and keeps going.
    assert!(result.is_err(), "expected a graceful per-file error");
    let _ = fs::remove_file(&js);
}

#[tokio::test]
async fn cached_provider_result_is_reused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(temp_config(dir.path(), None));
    let js = write_fixture(dir.path(), "first.js", b"var a = 1;\n");
    let hashes =
        unfamous::hashing::hash_file(&js, &[unfamous::hashing::HashAlgo::Sha256], 512, false)
            .expect("hash fixture");
    let sha256 = hashes.primary_sha256().expect("sha256").to_string();

    // Seed the cache with a malicious verdict, then verify the pipeline
    // consumes it without any provider being online.
    {
        let pipeline = Pipeline::build(config.clone()).expect("pipeline");
        let cache = pipeline.cache.as_ref().expect("cache");
        cache.put(
            unfamous::hashing::HashAlgo::Sha256,
            &sha256,
            "virustotal",
            &unfamous::providers::ProviderOutcome::Found(unfamous::providers::ProviderHit {
                verdict: unfamous::providers::Verdict::Malicious,
                malicious: Some(10),
                suspicious: Some(0),
                harmless: Some(50),
                engines: Some(60),
                first_seen: None,
                last_seen: None,
                tags: vec![],
                family: Some("TestFamily".into()),
                confidence: Some(0.9),
                summary: None,
            }),
            &config.cache,
        );
        assert!(cache.stats().entries > 0);
    }

    let pipeline = Pipeline::build(config).expect("pipeline");
    let alert = scan(&pipeline, &js).await.expect("alert expected");
    assert_eq!(
        alert.reputation,
        unfamous::reputation::ReputationVerdict::KnownBad
    );
    assert!(alert
        .provider_results
        .iter()
        .any(|r| r.provider == "virustotal"));
}
