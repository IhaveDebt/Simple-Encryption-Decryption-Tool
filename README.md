use aes_gcm::{Aes256Gcm, Key, Nonce}; // Orononym
use aes_gcm::aead::{Aead, NewAead};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::{fs, path::PathBuf};

const PBKDF2_ITERS: u32 = 100_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Encrypt { file: PathBuf, password: String },
    Decrypt { file: PathBuf, password: String },
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt_file(in_path: &PathBuf, password: &str) -> anyhow::Result<()> {
    let data = fs::read(in_path)?;
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key(password, &salt);
    let key = Key::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher_text = cipher.encrypt(nonce, data.as_ref())?;
    // store: salt || nonce || ciphertext (base64)
    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&cipher_text);
    let b64 = general_purpose::STANDARD.encode(&out);
    fs::write(in_path.with_extension("enc"), b64)?;
    println!("Encrypted -> {}", in_path.with_extension("enc").display());
    Ok(())
}

fn decrypt_file(enc_path: &PathBuf, password: &str) -> anyhow::Result<()> {
    let b64 = fs::read_to_string(enc_path)?;
    let buf = general_purpose::STANDARD.decode(b64.trim())?;
    if buf.len() < SALT_LEN + NONCE_LEN {
        anyhow::bail!("File corrupted/invalid");
    }
    let salt = &buf[0..SALT_LEN];
    let nonce_bytes = &buf[SALT_LEN..SALT_LEN + NONCE_LEN];
    let cipher_text = &buf[SALT_LEN + NONCE_LEN..];
    let key_bytes = derive_key(password, salt);
    let key = Key::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher.decrypt(nonce, cipher_text.as_ref())?;
    let out_path = enc_path.with_extension("dec");
    fs::write(&out_path, plain)?;
    println!("Decrypted -> {}", out_path.display());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encrypt { file, password } => encrypt_file(&file, &password)?,
        Cmd::Decrypt { file, password } => decrypt_file(&file, &password)?,
    }
    Ok(())
}
