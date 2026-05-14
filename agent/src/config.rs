use anyhow::{Context, Result};
use directories::ProjectDirs;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub token: String,
    pub bind: String,
}

impl Config {
    pub fn load_or_init() -> Result<Self> {
        let proj = ProjectDirs::from("cam", "bastion", "bastion")
            .context("could not resolve project dirs")?;
        let data_dir = proj.data_dir().to_path_buf();
        fs::create_dir_all(&data_dir)?;

        let token_path = data_dir.join("token.txt");
        let token = if token_path.exists() {
            fs::read_to_string(&token_path)?.trim().to_string()
        } else {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            let t = hex::encode(buf);
            fs::write(&token_path, &t)?;
            t
        };

        Ok(Self {
            data_dir,
            token,
            bind: "127.0.0.1:7878".into(),
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("bastion.db")
    }
}
