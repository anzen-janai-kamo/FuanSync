use fuansync::{
    binary, install,
    record::{self, CAPACITY},
};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
};
use tempfile::TempDir;

fn executable() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_fuansync"));
    if built.is_file() {
        return built;
    }
    // A target runtime may expose the build directory under a different root.
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(built.file_name().unwrap())
}
fn pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    })
}

fn command(exe: &Path, cwd: &Path, arguments: &[&str], input: &str) -> Output {
    let mut child = Command::new(exe)
        .current_dir(cwd)
        .args(arguments)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn git(cwd: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn helper_input_no_persistence_and_network_error_redaction() {
    let temp = TempDir::new().unwrap();
    let key = temp.path().join("key.pem");
    fs::write(&key, pem()).unwrap();
    let arguments = [
        "--app",
        "1",
        "--installation",
        "2",
        "--pem",
        key.to_str().unwrap(),
    ];
    for operation in ["store", "erase"] {
        let mut args = arguments.to_vec();
        args.push(operation);
        let output = command(
            &executable(),
            temp.path(),
            &args,
            "protocol=https\nhost=github.com\npassword=TOKEN_SECRET\n\n",
        );
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for input in [
        "protocol=http\nhost=github.com\n\n",
        "protocol=https\nhost=evil.com\n\n",
        "protocol=https\nhost=github.com\npassword=TOKEN_SECRET\n\n",
    ] {
        let output = command(&executable(), temp.path(), &arguments, input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("TOKEN_SECRET"));
        assert!(!error.contains("BEGIN PRIVATE KEY"));
        assert!(!error.contains("Bearer"));
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn output_modes_corruption_and_atomic_overwrite() {
    if cfg!(target_os = "macos") {
        return;
    }
    let temp = TempDir::new().unwrap();
    let key = temp.path().join("key.pem");
    fs::write(&key, pem()).unwrap();
    let path = temp.path().join("embedded");
    let args = [
        "--embed",
        "--app",
        "1",
        "--installation",
        "2",
        "--pem",
        key.to_str().unwrap(),
        "-o",
        path.to_str().unwrap(),
    ];
    let original = fs::read(executable()).unwrap();
    assert!(
        command(&executable(), temp.path(), &args, "")
            .status
            .success()
    );
    assert_eq!(fs::read(executable()).unwrap(), original);
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        binary::embedded_record(&bytes).unwrap().unwrap().len(),
        CAPACITY
    );
    assert_eq!(
        record::decode(binary::embedded_record(&bytes).unwrap().unwrap())
            .unwrap()
            .app,
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert!(
        !command(&executable(), temp.path(), &args, "")
            .status
            .success()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut forced = args.to_vec();
    forced.push("-f");
    assert!(
        command(&executable(), temp.path(), &forced, "")
            .status
            .success()
    );
    assert!(
        command(&path, temp.path(), &["--help"], "")
            .status
            .success()
    );
    assert!(
        command(&path, temp.path(), &["--version"], "")
            .status
            .success()
    );
    for forbidden in ["--app", "--installation", "--pem", "--embed", "-o", "-f"] {
        assert!(
            !command(&path, temp.path(), &[forbidden], "")
                .status
                .success()
        );
    }
    assert!(
        command(
            &path,
            temp.path(),
            &["store"],
            "protocol=https\nhost=github.com\n\n"
        )
        .status
        .success()
    );
    let mut invalid = bytes.clone();
    let record = binary::embedded_record(&invalid).unwrap().unwrap();
    let offset = record.as_ptr() as usize - invalid.as_ptr() as usize;
    invalid[offset] ^= 1;
    fs::write(&path, invalid).unwrap();
    let help = command(&path, temp.path(), &["--help"], "");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--app"));
    let oversized = temp.path().join("oversized.pem");
    fs::write(&oversized, vec![b'x'; 65537]).unwrap();
    let result = command(
        &executable(),
        temp.path(),
        &[
            "--embed",
            "--app",
            "1",
            "--installation",
            "2",
            "--pem",
            oversized.to_str().unwrap(),
            "-o",
            "absent",
        ],
        "",
    );
    assert!(!result.status.success());
    assert!(!temp.path().join("absent").exists());
    assert!(
        !command(
            &executable(),
            temp.path(),
            &[
                "--embed",
                "--app",
                "1",
                "--installation",
                "2",
                "--pem",
                key.to_str().unwrap(),
                "-o",
                executable().to_str().unwrap(),
                "-f"
            ],
            ""
        )
        .status
        .success()
    );
    assert_eq!(fs::read(executable()).unwrap(), original);
}

#[test]
fn installation_preserves_helpers_locks_and_quotes_paths() {
    if cfg!(target_os = "macos") {
        return;
    }
    let temp = TempDir::new().unwrap();
    let repo = temp.path().join("repo space ' $ with chars");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "--quiet"]);
    git(
        &repo,
        &["config", "--local", "--add", "credential.helper", "first"],
    );
    git(
        &repo,
        &["config", "--local", "--add", "credential.helper", ""],
    );
    git(
        &repo,
        &["config", "--local", "--add", "credential.helper", "third"],
    );
    let key = temp.path().join("key.pem");
    fs::write(&key, pem()).unwrap();
    let args = [
        "--embed",
        "--app",
        "1",
        "--installation",
        "2",
        "--pem",
        key.to_str().unwrap(),
    ];
    let installed = command(&executable(), &repo, &args, "");
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let path = repo.join(".git/.fuansync-credential-helper");
    let expected = format!(
        "first\n\nthird\n{}\n",
        install::helper_value(&fs::canonicalize(&path).unwrap()).unwrap()
    );
    assert_eq!(
        String::from_utf8(
            git(
                &repo,
                &["config", "--local", "--get-all", "credential.helper"]
            )
            .stdout
        )
        .unwrap(),
        expected
    );
    let config = fs::read(repo.join(".git/config")).unwrap();
    let helper = fs::read(&path).unwrap();
    assert!(!command(&executable(), &repo, &args, "").status.success());
    assert_eq!(fs::read(repo.join(".git/config")).unwrap(), config);
    assert_eq!(fs::read(&path).unwrap(), helper);
    let mut forced = args.to_vec();
    forced.push("-f");
    assert!(command(&executable(), &repo, &forced, "").status.success());
    assert_eq!(
        String::from_utf8(
            git(
                &repo,
                &["config", "--local", "--get-all", "credential.helper"]
            )
            .stdout
        )
        .unwrap(),
        expected
    );
    // Invoke through Git's actual shell dispatcher with a hostile origin.
    let output = command(
        Path::new("git"),
        &repo,
        &[
            "-c",
            "credential.helper=",
            "-c",
            &format!(
                "credential.helper={}",
                install::helper_value(&fs::canonicalize(&path).unwrap()).unwrap()
            ),
            "credential",
            "reject",
        ],
        "protocol=http\nhost=github.com\n\n",
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("only protocol=https"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::write(repo.join(".git/config.lock"), b"busy").unwrap();
    let config = fs::read(repo.join(".git/config")).unwrap();
    assert!(!command(&executable(), &repo, &forced, "").status.success());
    assert_eq!(fs::read(repo.join(".git/config")).unwrap(), config);
    assert_eq!(fs::read(&path).unwrap(), helper);
    assert_eq!(fs::read(repo.join(".git/config.lock")).unwrap(), b"busy");
    assert_eq!(
        fs::read_dir(repo.join(".git"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".tmp"))
            .count(),
        0
    );
}

#[test]
fn same_path_config_without_output_and_install_outside_repo() {
    if cfg!(target_os = "macos") {
        return;
    }
    let temp = TempDir::new().unwrap();
    git(temp.path(), &["init", "--quiet"]);
    let output = temp.path().join(".git/.fuansync-credential-helper");
    let value = install::helper_value(&output).unwrap();
    git(
        temp.path(),
        &["config", "--local", "--add", "credential.helper", &value],
    );
    let key = temp.path().join("key.pem");
    fs::write(&key, pem()).unwrap();
    let args = [
        "--embed",
        "--app",
        "1",
        "--installation",
        "2",
        "--pem",
        key.to_str().unwrap(),
    ];
    assert!(
        !command(&executable(), temp.path(), &args, "")
            .status
            .success()
    );
    assert!(!output.exists());
    let mut forced = args.to_vec();
    forced.push("-f");
    let installed = command(&executable(), temp.path(), &forced, "");
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let outside = TempDir::new().unwrap();
    assert!(
        !command(&executable(), outside.path(), &args, "")
            .status
            .success()
    );
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}
