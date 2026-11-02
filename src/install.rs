use crate::Result;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{NamedTempFile, TempPath};

fn git(cwd: &Path, arguments: &[&OsStr]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(arguments.iter().map(|argument| git_argument(argument)))
        .output()
        .map_err(|_| "cannot run Git")?;
    if !output.status.success() {
        return Err("Git repository/configuration operation failed");
    }
    Ok(output.stdout)
}

fn git_argument(argument: &OsStr) -> OsString {
    #[cfg(windows)]
    if let Some(text) = argument.to_str() {
        // Git for Windows can read Win32 extended paths but cannot create its
        // config lock beside them. Pass normal drive/UNC paths to Git.
        if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
            return OsString::from(format!("//{}", rest.replace('\\', "/")));
        }
        if let Some(rest) = text.strip_prefix("\\\\?\\") {
            return OsString::from(rest.replace('\\', "/"));
        }
    }
    argument.to_owned()
}

fn git_path(cwd: &Path, arguments: &[&OsStr]) -> Result<PathBuf> {
    let bytes = git(cwd, arguments).map_err(|_| "cannot locate Git repository paths")?;
    let path = std::str::from_utf8(&bytes)
        .map_err(|_| "Git path must be valid UTF-8")?
        .trim_end_matches(['\r', '\n']);
    let path = PathBuf::from(path);
    fs::canonicalize(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
    .map_err(|_| "cannot resolve Git path")
}

pub fn helper_value(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or("helper path must be valid UTF-8")?;
    if text.contains(['\n', '\r', '\0']) {
        return Err("unsupported helper path");
    }
    // Git executes helpers through a POSIX shell, including Git for Windows.
    let text = if cfg!(windows) {
        // canonicalize produces Windows extended-length paths. Git's shell uses
        // ordinary drive paths / UNC paths instead of the Win32 \\?\ prefix.
        let text = text
            .strip_prefix("\\\\?\\UNC\\")
            .map(|rest| format!("//{rest}"))
            .unwrap_or_else(|| text.strip_prefix("\\\\?\\").unwrap_or(text).to_owned());
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    // Keep the absolute-path prefix visible to Git's helper dispatcher.
    let mut escaped = String::new();
    for character in text.chars() {
        if !character.is_alphanumeric() && !"/:._-".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    Ok(escaped)
}

fn resolve_output(output: &Path, source: &Path) -> Result<PathBuf> {
    let name = output.file_name().ok_or("output requires a file name")?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = fs::canonicalize(parent)
        .map_err(|_| "output directory does not exist")?
        .join(name);
    let source = fs::canonicalize(source).map_err(|_| "cannot resolve input executable")?;
    if path == source {
        return Err("input executable must not be modified in place");
    }
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file() {
            return Err("output must be a regular file, not a symlink or directory");
        }
        if fs::canonicalize(&path).map_err(|_| "cannot resolve existing output")? == source {
            return Err("input executable must not be modified in place");
        }
    }
    Ok(path)
}

fn stage(path: &Path, bytes: &[u8]) -> Result<NamedTempFile> {
    let mut temporary = NamedTempFile::new_in(path.parent().ok_or("output directory missing")?)
        .map_err(|_| "cannot create temporary output")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot set output permissions")?;
    }
    temporary
        .write_all(bytes)
        .map_err(|_| "cannot write embedded output")?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| "cannot synchronize embedded output")?;
    Ok(temporary)
}

pub fn write_output(output: &Path, source: &Path, bytes: &[u8], force: bool) -> Result<PathBuf> {
    let path = resolve_output(output, source)?;
    if path.try_exists().map_err(|_| "cannot inspect output")? && !force {
        return Err("output exists; use -f to replace it");
    }
    let temporary = stage(&path, bytes)?;
    if force {
        temporary
            .persist(&path)
            .map_err(|_| "cannot publish embedded output")?;
    } else {
        temporary
            .persist_noclobber(&path)
            .map_err(|_| "output exists or cannot be published; use -f to replace it")?;
    }
    Ok(path)
}

struct ConfigLock {
    path: PathBuf,
    file: Option<File>,
}
impl Drop for ConfigLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

pub fn install(cwd: &Path, source: &Path, bytes: &[u8], force: bool) -> Result<PathBuf> {
    let directory = git_path(
        cwd,
        &[OsStr::new("rev-parse"), OsStr::new("--absolute-git-dir")],
    )?;
    let config = git_path(
        cwd,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--git-path"),
            OsStr::new("config"),
        ],
    )?;
    let path = resolve_output(&directory.join(".fuansync-credential-helper"), source)?;
    let value = helper_value(&path)?;
    let lock_path = config.with_file_name(format!(
        "{}.lock",
        config
            .file_name()
            .ok_or("invalid Git configuration path")?
            .to_string_lossy()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|_| "Git configuration is locked or not writable")?;
    let mut lock = ConfigLock {
        path: lock_path,
        file: Some(file),
    };
    let config_bytes = fs::read(&config).map_err(|_| "cannot read Git configuration")?;
    let permissions = fs::metadata(&config)
        .map_err(|_| "cannot inspect Git configuration")?
        .permissions();
    lock.file
        .as_mut()
        .ok_or("configuration lock is closed")?
        .set_permissions(permissions)
        .map_err(|_| "cannot set Git configuration permissions")?;
    let mut prepared =
        NamedTempFile::new_in(config.parent().ok_or("configuration directory missing")?)
            .map_err(|_| "cannot stage Git configuration")?;
    prepared
        .write_all(&config_bytes)
        .map_err(|_| "cannot stage Git configuration")?;
    // Git replaces the file while editing it. Close our file handle before
    // invoking Git so Windows permits that replacement.
    let prepared = prepared.into_temp_path();
    let query = Command::new("git")
        .current_dir(cwd)
        .arg("config")
        .arg("--file")
        .arg(git_argument(prepared.as_os_str()))
        .args(["--null", "--get-all", "credential.helper"])
        .output()
        .map_err(|_| "cannot inspect helper configuration")?;
    if !query.status.success() && query.status.code() != Some(1) {
        return Err("cannot inspect helper configuration");
    }
    let raw = path.to_str().ok_or("helper path must be valid UTF-8")?;
    let mut matches = Vec::new();
    for current in query
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
    {
        if current == value.as_bytes() || current == raw.as_bytes() {
            matches.push(
                std::str::from_utf8(current)
                    .map_err(|_| "invalid helper configuration")?
                    .to_owned(),
            );
        }
    }
    if !force
        && (!matches.is_empty()
            || path
                .try_exists()
                .map_err(|_| "cannot inspect installed helper")?)
    {
        return Err("helper output or same-path configuration exists; use -f to replace it");
    }
    for current in matches {
        git(
            cwd,
            &[
                OsStr::new("config"),
                OsStr::new("--file"),
                prepared.as_os_str(),
                OsStr::new("--fixed-value"),
                OsStr::new("--unset-all"),
                OsStr::new("credential.helper"),
                OsStr::new(&current),
            ],
        )
        .map_err(|_| "cannot remove previous same-path helper configuration")?;
    }
    git(
        cwd,
        &[
            OsStr::new("config"),
            OsStr::new("--file"),
            prepared.as_os_str(),
            OsStr::new("--add"),
            OsStr::new("credential.helper"),
            OsStr::new(&value),
        ],
    )
    .map_err(|_| "cannot append helper configuration")?;
    let next_config = fs::read(&prepared).map_err(|_| "cannot read prepared configuration")?;
    lock.file
        .as_mut()
        .ok_or("configuration lock is closed")?
        .write_all(&next_config)
        .map_err(|_| "cannot prepare Git configuration lock")?;
    lock.file
        .as_mut()
        .ok_or("configuration lock is closed")?
        .sync_all()
        .map_err(|_| "cannot synchronize Git configuration")?;
    let staged = stage(&path, bytes)?;
    let backup: Option<TempPath> = if path
        .try_exists()
        .map_err(|_| "cannot inspect helper output")?
    {
        let temporary = NamedTempFile::new_in(&directory)
            .map_err(|_| "cannot reserve helper backup")?
            .into_temp_path();
        // On Windows rename cannot replace an existing destination.
        fs::remove_file(&temporary).map_err(|_| "cannot prepare helper backup")?;
        fs::rename(&path, &temporary).map_err(|_| "cannot preserve previous helper")?;
        Some(temporary)
    } else {
        None
    };
    if staged.persist_noclobber(&path).is_err() {
        if let Some(backup) = backup
            && fs::rename(&backup, &path).is_err()
        {
            let _ = backup.keep();
            return Err("helper installation and rollback failed");
        }
        return Err("cannot publish helper output");
    }
    // Close the lock file first: Windows cannot rename an open destination.
    drop(lock.file.take());
    if fs::rename(&lock.path, &config).is_err() {
        let removed = fs::remove_file(&path).is_ok();
        let restored = backup
            .map(|backup| {
                if fs::rename(&backup, &path).is_ok() {
                    true
                } else {
                    let _ = backup.keep();
                    false
                }
            })
            .unwrap_or(true);
        if !removed || !restored {
            return Err("Git configuration update and helper rollback failed");
        }
        return Err("cannot publish Git configuration; helper output rolled back");
    }
    Ok(path)
}
