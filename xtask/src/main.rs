use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::Command,
};

mod mutation;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Audit tests using compiling, one-at-a-time faults in an isolated source copy.
    Mutate {
        /// Run Linux socket cases (requires Linux, never contacts an SSH server).
        #[arg(long)]
        linux: bool,
        /// Restrict the audit to comma-separated mutation IDs.
        #[arg(long)]
        only: Option<String>,
        #[arg(long, default_value = "audit")]
        label: String,
    },
    /// Bundle a pre-built macOS executable as dist/Remi.app.
    Bundle {
        #[arg(long, default_value = "target/release/remi")]
        binary: PathBuf,
    },
    /// Build a .deb from Linux binaries, with Rust lifecycle hooks.
    Deb {
        #[arg(long)]
        arch: String,
        #[arg(long, default_value = "target/release")]
        binaries: PathBuf,
        #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
        version: String,
    },
    /// Generate an APT repository and sign its Release metadata with GPG.
    Apt {
        #[arg(long)]
        signing_key: String,
        #[arg(long, default_value = "dist")]
        packages: PathBuf,
        #[arg(long, default_value = "dist/apt")]
        output: PathBuf,
    },
}
fn main() -> Result<()> {
    match Cli::parse().action {
        Action::Mutate { linux, only, label } => mutation::run(linux, only.as_deref(), &label),
        Action::Bundle { binary } => bundle(&binary),
        Action::Deb {
            arch,
            binaries,
            version,
        } => deb(&arch, &binaries, &version),
        Action::Apt {
            signing_key,
            packages,
            output,
        } => apt(&signing_key, &packages, &output),
    }
}
fn command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        bail!("{program} failed: {status}");
    }
    Ok(())
}
fn bundle(binary: &Path) -> Result<()> {
    let root = Path::new("dist/Remi.app/Contents");
    fs::create_dir_all(root.join("MacOS"))?;
    fs::create_dir_all(root.join("Resources"))?;
    fs::copy(binary, root.join("MacOS/remi")).context("Primero compila remi-desktop")?;
    fs::copy("packaging/Info.plist", root.join("Info.plist"))?;
    let mut icns = Vec::from(&b"icns\0\0\0\0"[..]);
    for (size, kind) in [(128, b"ic07"), (256, b"ic08"), (512, b"ic09")] {
        let bytes = icon_png(size)?;
        icns.extend_from_slice(kind);
        icns.extend_from_slice(&((bytes.len() + 8) as u32).to_be_bytes());
        icns.extend_from_slice(&bytes);
    }
    let size = icns.len() as u32;
    icns[4..8].copy_from_slice(&size.to_be_bytes());
    fs::write(root.join("Resources/Remi.icns"), icns)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("MacOS/remi"), fs::Permissions::from_mode(0o755))?;
    }
    command(
        "codesign",
        &["--force", "--deep", "--sign", "-", "dist/Remi.app"],
    )?;
    println!("Created dist/Remi.app (local ad-hoc signature)");
    Ok(())
}
fn icon_png(size: usize) -> Result<Vec<u8>> {
    let mut rgba = vec![0; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 / size as f32;
            let fy = y as f32 / size as f32;
            let inside = (fx - 0.5).abs().powf(5.) + (fy - 0.5).abs().powf(5.) < 0.018;
            let eye = (fx - 0.35).powi(2) + (fy - 0.44).powi(2) < 0.003
                || (fx - 0.65).powi(2) + (fy - 0.44).powi(2) < 0.003;
            let smile = fy > 0.56 && fy < 0.59 && fx > 0.38 && fx < 0.62;
            let color = if eye || smile {
                [240, 246, 228, 255]
            } else if inside {
                [38, 102, 83, 255]
            } else {
                [0, 0, 0, 0]
            };
            rgba[(y * size + x) * 4..(y * size + x) * 4 + 4].copy_from_slice(&color);
        }
    }
    let mut result = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut result, size as u32, size as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header()?.write_image_data(&rgba)?;
    }
    Ok(result)
}
fn tar_entry(
    builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, Cursor::new(bytes))?;
    Ok(())
}
fn ar_member(file: &mut fs::File, name: &str, bytes: &[u8]) -> Result<()> {
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        format!("{name}/"),
        0,
        0,
        0,
        "100644",
        bytes.len()
    );
    if header.len() != 60 {
        bail!("Invalid ar header");
    }
    file.write_all(header.as_bytes())?;
    file.write_all(bytes)?;
    if bytes.len() % 2 == 1 {
        file.write_all(b"\n")?;
    }
    Ok(())
}
fn tar_directory(builder: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, std::io::empty())?;
    Ok(())
}
fn deb(arch: &str, binaries: &Path, version: &str) -> Result<()> {
    if !matches!(arch, "amd64" | "arm64")
        || version.is_empty()
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-~".contains(c))
    {
        bail!("Invalid architecture or version");
    }
    let binary = fs::read(binaries.join("remi-agent"))?;
    let helper = fs::read(binaries.join("remi-package"))?;
    for bytes in [&binary, &helper] {
        if bytes.get(..4) != Some(b"\x7fELF") {
            bail!("Debian requires Linux ELF binaries");
        }
        let machine = bytes.get(18..20).context("Truncated ELF")?;
        if machine != if arch == "arm64" { &[183, 0] } else { &[62, 0] } {
            bail!("Binary architecture does not match package");
        }
    }
    let control = format!(
        "Package: remi-agent\nVersion: {version}\nSection: admin\nPriority: optional\nArchitecture: {arch}\nMaintainer: Remi contributors <remi@localhost>\nDepends: libc6 (>= 2.36), libgcc-s1, systemd, init-system-helpers, passwd\nDescription: SSH login observation for Debian\n Records successful SSH logins and streams metadata to Remi over SSH.\n The observer runs as a dedicated system user and opens no TCP port.\n"
    );
    let mut controls = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::best()));
    tar_entry(&mut controls, "control", control.as_bytes(), 0o644)?;
    tar_entry(&mut controls, "conffiles", b"/etc/remi/agent.toml\n", 0o644)?;
    for name in ["postinst", "prerm", "postrm"] {
        tar_entry(&mut controls, name, &helper, 0o755)?;
    }
    let controls = controls.into_inner()?.finish()?;
    let mut data = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::best()));
    for directory in [
        "etc",
        "etc/remi",
        "usr",
        "usr/bin",
        "usr/lib",
        "usr/lib/systemd",
        "usr/lib/systemd/system",
        "usr/share",
        "usr/share/doc",
        "usr/share/doc/remi-agent",
    ] {
        tar_directory(&mut data, directory)?;
    }
    tar_entry(&mut data, "usr/bin/remi-agent", &binary, 0o755)?;
    for (source, destination) in [
        ("packaging/agent.toml", "etc/remi/agent.toml"),
        (
            "packaging/remi-agent.service",
            "usr/lib/systemd/system/remi-agent.service",
        ),
        ("README.md", "usr/share/doc/remi-agent/README.md"),
        ("LICENSE", "usr/share/doc/remi-agent/copyright"),
    ] {
        tar_entry(&mut data, destination, &fs::read(source)?, 0o644)?;
    }
    let data = data.into_inner()?.finish()?;
    fs::create_dir_all("dist")?;
    let path = format!("dist/remi-agent_{version}_{arch}.deb");
    let mut file = fs::File::create(&path)?;
    file.write_all(b"!<arch>\n")?;
    ar_member(&mut file, "debian-binary", b"2.0\n")?;
    ar_member(&mut file, "control.tar.gz", &controls)?;
    ar_member(&mut file, "data.tar.gz", &data)?;
    let checksum = format!(
        "{:x}  {}\n",
        Sha256::digest(fs::read(&path)?),
        Path::new(&path).file_name().unwrap().to_string_lossy()
    );
    fs::write(format!("{path}.sha256"), checksum)?;
    println!("Created {path}");
    Ok(())
}
fn apt(signing_key: &str, packages: &Path, root: &Path) -> Result<()> {
    if signing_key.starts_with('-') || signing_key.is_empty() {
        bail!("A signing key is required");
    }
    let mut entries = std::collections::BTreeMap::<String, String>::new();
    fs::create_dir_all(root.join("pool/main/r/remi-agent"))?;
    for item in fs::read_dir(packages)? {
        let path = item?.path();
        if path.extension().is_none_or(|ext| ext != "deb") {
            continue;
        }
        let bytes = fs::read(&path)?;
        let output = Command::new("dpkg-deb")
            .arg("--field")
            .arg(&path)
            .output()?;
        if !output.status.success() {
            bail!("Invalid .deb: {}", path.display());
        }
        let fields = String::from_utf8(output.stdout)?;
        let arch = fields
            .lines()
            .find_map(|line| line.strip_prefix("Architecture: "))
            .context("Missing architecture")?;
        if !matches!(arch, "arm64" | "amd64") {
            continue;
        }
        let filename = format!(
            "pool/main/r/remi-agent/{}",
            path.file_name().unwrap().to_string_lossy()
        );
        fs::write(root.join(&filename), &bytes)?;
        entries
            .entry(arch.to_string())
            .or_default()
            .push_str(&format!(
                "{}\nFilename: {filename}\nSize: {}\nSHA256: {:x}\nSHA512: {:x}\n\n",
                fields.trim_end(),
                bytes.len(),
                Sha256::digest(&bytes),
                Sha512::digest(&bytes)
            ));
    }
    if entries.is_empty() {
        bail!("No Debian packages found");
    }
    let distribution = root.join("dists/stable");
    let mut sums = String::new();
    for (arch, packages) in &entries {
        let relative = format!("main/binary-{arch}/Packages");
        let path = distribution.join(&relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, packages)?;
        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(packages.as_bytes())?;
        let gz = gz.finish()?;
        fs::write(path.with_extension("gz"), &gz)?;
        for (name, bytes) in [
            (relative.clone(), packages.as_bytes()),
            (format!("{relative}.gz"), gz.as_slice()),
        ] {
            sums.push_str(&format!(
                " {:x} {} {name}\n",
                Sha256::digest(bytes),
                bytes.len()
            ));
        }
    }
    let release = format!(
        "Origin: Remi\nLabel: Remi\nSuite: stable\nCodename: stable\nArchitectures: {}\nComponents: main\nDate: {}\nDescription: Remi signed APT repository\nSHA256:\n{sums}",
        entries.keys().cloned().collect::<Vec<_>>().join(" "),
        chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")
    );
    fs::write(distribution.join("Release"), release)?;
    for (mode, output) in [
        ("--clearsign", "InRelease"),
        ("--detach-sign", "Release.gpg"),
    ] {
        command(
            "gpg",
            &[
                "--batch",
                "--yes",
                "--local-user",
                signing_key,
                "--armor",
                "--output",
                distribution.join(output).to_str().unwrap(),
                mode,
                distribution.join("Release").to_str().unwrap(),
            ],
        )?;
    }
    let public_key = Command::new("gpg")
        .args([
            "--batch",
            "--export-options",
            "export-minimal",
            "--armor",
            "--export",
            signing_key,
        ])
        .output()?;
    if !public_key.status.success() || public_key.stdout.is_empty() {
        bail!("Could not export repository key");
    }
    fs::write(root.join("remi-archive-keyring.asc"), public_key.stdout)?;
    println!("Signed APT repository: {}", root.display());
    Ok(())
}
