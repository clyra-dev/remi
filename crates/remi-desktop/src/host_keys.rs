//! Strict OpenSSH host trust checks, including revoked keys and hashed hostnames.
use anyhow::{Context, Result, bail};
use ring::hmac;
use russh::keys::ssh_key::{
    PublicKey,
    known_hosts::{Entry, HostPatterns, Marker},
};
use std::{fs, io::ErrorKind, path::Path};

#[derive(Debug, PartialEq)]
pub enum Trust {
    Verified,
    Unknown,
}

pub fn read(path: &Path) -> Result<String> {
    match fs::metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).context("No se puede leer known_hosts"),
        Ok(metadata) => {
            if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
                bail!("known_hosts no es un archivo válido o es demasiado grande");
            }
            fs::read_to_string(path).context("No se puede leer known_hosts; revisa sus permisos")
        }
    }
}

pub fn verify(contents: &str, host: &str, port: u16, key: &PublicKey) -> Result<Trust> {
    let host = host.to_ascii_lowercase();
    let endpoint = if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    };
    let mut found = false;
    let mut verified = false;
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The parser expects single spaces; normalize whitespace and discard comments.
        let count = if line.starts_with('@') { 4 } else { 3 };
        let normalized = line
            .split_whitespace()
            .take(count)
            .collect::<Vec<_>>()
            .join(" ");
        let entry: Entry = normalized.parse().with_context(|| {
            format!(
                "known_hosts contiene una entrada inválida en la línea {}",
                index + 1
            )
        })?;
        if !matches_host(entry.host_patterns(), &endpoint) {
            continue;
        }
        found = true;
        let same_key = entry.public_key().key_data() == key.key_data();
        match entry.marker() {
            Some(Marker::Revoked) if same_key => {
                bail!("La llave SSH del servidor está revocada en known_hosts")
            }
            Some(_) => (), // CA entries cannot authenticate a plain host key.
            None if same_key => verified = true,
            None => (),
        }
    }
    if verified {
        Ok(Trust::Verified)
    } else if found {
        bail!(
            "La identidad SSH no coincide con known_hosts; verifica el servidor antes de conectar"
        )
    } else {
        Ok(Trust::Unknown)
    }
}

fn matches_host(patterns: &HostPatterns, host: &str) -> bool {
    match patterns {
        HostPatterns::HashedName { salt, hash } => {
            let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
            hmac::verify(&key, host.as_bytes(), hash).is_ok()
        }
        HostPatterns::Patterns(patterns) => {
            let mut positive = false;
            for pattern in patterns {
                let (negated, pattern) = pattern
                    .strip_prefix('!')
                    .map(|pattern| (true, pattern))
                    .unwrap_or((false, pattern.as_str()));
                if wildcard_match(&pattern.to_ascii_lowercase(), host) {
                    if negated {
                        return false;
                    }
                    positive = true;
                }
            }
            positive
        }
    }
}

// OpenSSH's host patterns use '*' and '?', with literal brackets around host:port.
fn wildcard_match(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.as_bytes(), host.as_bytes());
    let (mut p, mut h, mut star, mut retry) = (0, 0, None, 0);
    while h < host.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == host[h]) {
            p += 1;
            h += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = h;
        } else if let Some(position) = star {
            retry += 1;
            h = retry;
            p = position + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn remember(path: &Path, host: &str, port: u16, key: &PublicKey) -> Result<()> {
    let mut contents = read(path)?;
    if verify(&contents, host, port, key)? == Trust::Verified {
        return Ok(());
    }
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    let host = host.to_ascii_lowercase();
    let endpoint = if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    };
    contents.push_str(&format!("{endpoint} {}\n", key.to_openssh()?));
    remi_core::atomic_write(path, contents.as_bytes()).with_context(|| {
        format!(
            "No se pudo guardar la identidad del servidor en {}; revisa la ruta y sus permisos",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBBFy4/1MtRbkgvfdaPX8Z5pYHaxGEhdtB7stG3UAvi";
    const B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7rtBseAQPXJl3HIfH05NvOj3cys47Lq+N8bUbYYINj";
    fn key() -> PublicKey {
        A.parse().unwrap()
    }
    #[test]
    fn unknown_and_changed_hosts_are_distinct() {
        assert_eq!(verify("", "host", 22, &key()).unwrap(), Trust::Unknown);
        assert!(verify(&format!("host {B}"), "host", 22, &key()).is_err());
    }
    #[test]
    fn accepts_tabs_comments_case_and_multiple_valid_rotation_keys() {
        let entries = format!("  # comment\nHOST\t{B}\n host   {A} test comment\n");
        assert_eq!(
            verify(&entries, "HOST", 22, &key()).unwrap(),
            Trust::Verified
        );
    }
    #[test]
    fn revoked_key_overrides_an_otherwise_valid_entry() {
        let entries = format!("host {A}\n@revoked host {A}\n");
        assert!(
            verify(&entries, "host", 22, &key())
                .unwrap_err()
                .to_string()
                .contains("revocada")
        );
    }
    #[test]
    fn cert_authority_cannot_authorize_a_plain_host_key() {
        assert!(verify(&format!("@cert-authority host {A}"), "host", 22, &key()).is_err());
    }
    #[test]
    fn port_globs_and_negated_hosts_are_respected() {
        let entry = format!("[*.example.com]:2222,![blocked.example.com]:2222 {A}");
        assert_eq!(
            verify(&entry, "ok.example.com", 2222, &key()).unwrap(),
            Trust::Verified
        );
        assert_eq!(
            verify(&entry, "blocked.example.com", 2222, &key()).unwrap(),
            Trust::Unknown
        );
        assert_eq!(
            verify(&entry, "ok.example.com", 22, &key()).unwrap(),
            Trust::Unknown
        );
        assert!(wildcard_match("a?c*", "abcd"));
        assert!(!wildcard_match("a?c", "abcd"));
    }
    #[test]
    fn hashed_names_match_only_their_original_host() {
        // A fixed HMAC fixture, produced by ssh-keygen -H, for example.com.
        let entry = format!("|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= {A}");
        assert_eq!(
            verify(&entry, "example.com", 22, &key()).unwrap(),
            Trust::Verified
        );
        assert_eq!(
            verify(&entry, "other.example.com", 22, &key()).unwrap(),
            Trust::Unknown
        );
    }
    #[test]
    fn refuses_invalid_files_and_does_not_replace_changed_identity() {
        assert!(verify("host broken", "host", 22, &key()).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).is_err());
        let path = dir.path().join("known_hosts");
        let original = format!("host {B}\n");
        fs::write(&path, &original).unwrap();
        let error = remember(&path, "host", 22, &key()).unwrap_err().to_string();
        assert!(error.contains("no coincide"), "{error}");
        assert_eq!(fs::read_to_string(path).unwrap(), original);
    }
    #[test]
    fn failed_write_names_the_known_hosts_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let path = dir.path().join("known_hosts");
        let result = remember(&path, "host", 22, &key());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains("permisos"), "{error}");
    }
    #[test]
    fn explicit_trust_is_durable_private_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        remember(&path, "Host", 2222, &key()).unwrap();
        remember(&path, "Host", 2222, &key()).unwrap();
        let contents = read(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert_eq!(
            verify(&contents, "host", 2222, &key()).unwrap(),
            Trust::Verified
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
