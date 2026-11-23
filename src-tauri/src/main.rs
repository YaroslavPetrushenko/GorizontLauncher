#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod db;
mod http_server;
mod servers;

use auth::{AuthResponse, LoginRequest, RegisterRequest, RefreshRequest, LogoutRequest, ForgotPasswordRequest, OAuthRequest, DbPool};
use db::init_db;
use futures_util::StreamExt;
use http_server::start_http_server;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, env, fs, io::{self, Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use zip::ZipArchive;

/// Public key (Ed25519, base64) that signs every modpack release. The private key never leaves the build owner's machine.
const PACK_PUBLIC_KEY_B64: &str = "a8m9ZliWQz/Ty2SCl4iE/boPMs+ovtc6tPefWxH5go4=";

/// Checks modpack.sig: an Ed25519 signature over the SHA-256 digest of the modpack.zip bytes.
fn verify_modpack_signature(zip_bytes: &[u8], signature_b64: &str) -> Result<(), String> {
    use base64::Engine;
    let public = base64::engine::general_purpose::STANDARD.decode(PACK_PUBLIC_KEY_B64).map_err(|e| e.to_string())?;
    let signature = base64::engine::general_purpose::STANDARD.decode(signature_b64.trim()).map_err(|_| "Некорректная подпись сборки".to_string())?;
    let digest = Sha256::digest(zip_bytes);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(&digest, &signature)
        .map_err(|_| "Подпись сборки не совпадает: архив изменён или подписан не автором сборки".to_string())
}

const JAVA_DOWNLOAD_URL: &str = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse";

/// Account currently signed in inside the launcher.
/// The Bukkit plugin asks the launcher over HTTP whether a joining player is
/// signed in here, so players from our launcher never need /login.
#[derive(Clone, Debug)]
pub struct ActiveAccount {
    pub nickname: String,
    pub user_id: String,
    pub expires_at: i64,
}

pub type ActiveAccountState = Arc<RwLock<Option<ActiveAccount>>>;

/// Remember the signed-in account (decoded from the freshly issued access token).
fn remember_active_account(active: &ActiveAccountState, response: &AuthResponse) {
    match auth::decode_token(&response.access_token) {
        Ok(claims) if claims.typ == "access" => {
            let mut guard = active.write().unwrap_or_else(|e| e.into_inner());
            *guard = Some(ActiveAccount { nickname: claims.nickname, user_id: claims.sub, expires_at: claims.exp });
        }
        Ok(_) => eprintln!("[AUTH] Issued token is not an access token, active account not set"),
        Err(e) => eprintln!("[AUTH] Could not decode access token: {e}"),
    }
}

fn webhook_url() -> String {
    env::var("WEBHOOK_URL").unwrap_or_default()
}

fn webhook_token() -> String {
    env::var("WEBHOOK_TOKEN").unwrap_or_default()
}

fn expand_windows_path(input: &str) -> PathBuf {
    let mut value = input.to_string();
    if value.contains("%APPDATA%") {
        if let Ok(app_data) = env::var("APPDATA") {
            value = value.replace("%APPDATA%", &app_data);
        }
    }
    if value.contains("%LOCALAPPDATA%") {
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            value = value.replace("%LOCALAPPDATA%", &local_app_data);
        }
    }
    PathBuf::from(value.replace('/', "\\"))
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn ensure_assets(target: &Path) -> Result<(), String> {
    // Copy libraries from default .minecraft if missing
    let libs_dir = target.join("libraries");
    let libs_exist = libs_dir.exists() && libs_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    if !libs_exist {
        let default_mc = env::var("APPDATA").map(|a| PathBuf::from(a).join(".minecraft")).unwrap_or_default();
        let default_libs = default_mc.join("libraries");
        if default_libs.exists() {
            eprintln!("[ASSETS] Copying libraries from {}", default_libs.display());
            copy_dir_all(&default_libs, &libs_dir).map_err(|e| format!("Не удалось скопировать библиотеки: {e}"))?;
            eprintln!("[ASSETS] Libraries copied");
        }
    }

    // Copy assets (indexes/objects) from default .minecraft if missing
    let assets_dir = target.join("assets");
    if !assets_dir.join("indexes").exists() {
        let default_assets = env::var("APPDATA").map(|a| PathBuf::from(a).join(".minecraft").join("assets")).unwrap_or_default();
        if default_assets.exists() {
            eprintln!("[ASSETS] Copying assets from {}", default_assets.display());
            copy_dir_all(&default_assets, &assets_dir).map_err(|e| format!("Не удалось скопировать assets: {e}"))?;
            eprintln!("[ASSETS] Assets copied");
        }
    }

    // Copy mods from default .minecraft if missing
    let mods_dir = target.join("mods");
    let mods_exist = mods_dir.exists() && mods_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    if !mods_exist {
        let default_mc = env::var("APPDATA").map(|a| PathBuf::from(a).join(".minecraft")).unwrap_or_default();
        let default_mods = default_mc.join("mods");
        if default_mods.exists() {
            eprintln!("[ASSETS] Copying mods from {}", default_mods.display());
            copy_dir_all(&default_mods, &mods_dir).map_err(|e| format!("Не удалось скопировать моды: {e}"))?;
            eprintln!("[ASSETS] Mods copied");
        }
    }

    // Copy config from default .minecraft if missing
    let config_dir = target.join("config");
    let config_exist = config_dir.exists() && config_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    if !config_exist {
        let default_mc = env::var("APPDATA").map(|a| PathBuf::from(a).join(".minecraft")).unwrap_or_default();
        let default_config = default_mc.join("config");
        if default_config.exists() {
            eprintln!("[ASSETS] Copying config from {}", default_config.display());
            copy_dir_all(&default_config, &config_dir).map_err(|e| format!("Не удалось скопировать конфиг: {e}"))?;
            eprintln!("[ASSETS] Config copied");
        }
    }

    Ok(())
}

fn launcher_data_dir() -> Result<PathBuf, String> {
    let base = env::var("LOCALAPPDATA").map_err(|_| "Не удалось определить LOCALAPPDATA".to_string())?;
    let path = PathBuf::from(base).join("GorizontLauncher"); fs::create_dir_all(&path).map_err(|e| e.to_string())?; Ok(path)
}

#[derive(Deserialize, Clone)]
struct LauncherConfig {
    github_owner: String,
    github_repo: String,
    modpack_asset: String,
    expected_manifest: String,
    pack_id: String,
    minecraft_version: String,
    #[serde(default)]
    loader_type: String,
    #[serde(default)]
    loader_version: String,
    server_address: String,
    server_port: u16,
    #[serde(default)]
    local_modpack_path: Option<String>,
    /// Explicit URL of the additional mods catalog (JSON). Empty/unset means:
    /// look for a release asset named by `extra_mods_catalog_asset`.
    #[serde(default)]
    extra_mods_catalog_url: Option<String>,
    /// Release asset name that holds the additional mods catalog.
    #[serde(default)]
    extra_mods_catalog_asset: Option<String>,
    /// Port of the local HTTP API the Bukkit plugin talks to.
    #[serde(default = "default_launcher_api_port")]
    launcher_api_port: u16,
    /// Base URL of the server auth API (the Bukkit plugin listens there).
    #[serde(default = "default_server_api_url")]
    server_api_url: String,
}

fn default_server_api_url() -> String { "http://gp-ru-2.apexnodes.xyz:22754".to_string() }

fn default_launcher_api_port() -> u16 { 22754 }

fn resolve_effective_config(config: &LauncherConfig, override_opt: &Option<VersionOverride>) -> LauncherConfig {
    match override_opt {
        Some(ov) => LauncherConfig {
            minecraft_version: ov.minecraft_version.clone().unwrap_or_else(|| config.minecraft_version.clone()),
            loader_type: ov.loader_type.clone().unwrap_or_else(|| config.loader_type.clone()),
            loader_version: ov.loader_version.clone().unwrap_or_else(|| config.loader_version.clone()),
            ..config.clone()
        },
        None => config.clone(),
    }
}

#[derive(Deserialize, Serialize)]
struct PackManifest {
    schema_version: u32,
    pack_id: String,
    pack_version: String,
    minecraft_version: String,
    loader: LoaderManifest,
}

/// File integrity manifest: maps relative file paths to their SHA256 hashes
#[derive(Deserialize, Serialize)]
struct FileIntegrityManifest {
    pack_version: String,
    files: HashMap<String, String>, // relative_path -> sha256 hex
}

/// User mod entry: a mod installed by the user that should persist across updates
#[derive(Deserialize, Serialize, Clone, Debug)]
struct UserMod {
    /// Unique identifier (filename without .jar)
    id: String,
    /// Original filename
    filename: String,
    /// SHA256 hash of the mod file
    hash: String,
    /// Whether the mod is enabled
    enabled: bool,
    /// Whether the user has approved this mod to persist across updates
    approved: bool,
    /// Mod display name (optional, can be extracted from filename)
    display_name: Option<String>,
    /// Mod version (optional)
    version: Option<String>,
}

/// User mods manifest: stores all user-installed mods with their metadata
#[derive(Deserialize, Serialize, Default)]
struct UserModsManifest {
    mods: HashMap<String, UserMod>, // id -> UserMod
}

/// One additional (optional) mod offered by the catalog.
#[derive(Deserialize, Serialize, Clone, Debug)]
struct ExtraModSpec {
    /// Stable identifier used by the UI and by installed-state tracking.
    id: String,
    /// Human readable mod name.
    name: String,
    /// Mod version string.
    #[serde(default)]
    version: Option<String>,
    /// Short description shown in the launcher.
    #[serde(default)]
    description: Option<String>,
    /// File name written into the game `mods/` directory.
    filename: String,
    /// Direct download URL (GitHub release asset or any https URL).
    url: String,
    /// Expected SHA256 (hex). When present the download is verified.
    #[serde(default)]
    sha256: Option<String>,
    /// Expected size in bytes (informational, used for progress totals).
    #[serde(default)]
    size: Option<u64>,
    /// Minecraft version this mod is built for.
    #[serde(default)]
    minecraft_version: Option<String>,
    /// Mod loader this mod is built for (`neoforge`).
    #[serde(default)]
    loader: Option<String>,
}

/// Catalog of additional mods plus where it came from.
#[derive(Deserialize, Serialize, Clone, Debug)]
struct ExtraModsCatalog {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    mods: Vec<ExtraModSpec>,
}

/// Catalog together with the run-time status the UI needs.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ExtraModsResponse {
    /// Where the catalog was loaded from (URL) or an empty string when unavailable.
    source: String,
    /// Mods with their local installation state.
    mods: Vec<ExtraModState>,
    /// Human readable reason when the catalog could not be loaded.
    error: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ExtraModState {
    id: String,
    name: String,
    version: Option<String>,
    description: Option<String>,
    filename: String,
    url: String,
    sha256: Option<String>,
    size: Option<u64>,
    minecraft_version: Option<String>,
    loader: Option<String>,
    /// True when the exact file with the catalog hash already exists in mods/.
    installed: bool,
    /// True when a file with this name exists but its hash differs.
    outdated: bool,
    /// True when this file name belongs to the base modpack (never overwritten).
    in_modpack: bool,
}

/// Parse the additional mods catalog from raw JSON text.
fn parse_extra_mods_catalog(text: &str) -> Result<ExtraModsCatalog, String> {
    let catalog: ExtraModsCatalog = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("Некорректный каталог дополнительных модов: {e}"))?;
    for m in &catalog.mods {
        if m.id.trim().is_empty() || m.name.trim().is_empty() || m.filename.trim().is_empty() || m.url.trim().is_empty() {
            return Err("В каталоге дополнительных модов есть запись без id, name, filename или url".into());
        }
        if !m.filename.to_lowercase().ends_with(".jar") {
            return Err(format!("Файл дополнительного мода должен быть .jar: {}", m.filename));
        }
        if m.filename.contains('/') || m.filename.contains('\\') {
            return Err(format!("Недопустимое имя файла в каталоге: {}", m.filename));
        }
        if !m.url.to_lowercase().starts_with("https://") {
            return Err(format!("Ссылка на мод должна быть https: {}", m.url));
        }
    }
    Ok(catalog)
}

/// Cache file for the catalog so the UI keeps working offline.
fn extra_mods_cache_path(game_path: &Path) -> PathBuf {
    game_path.join(".gorizont-extra-mods-catalog.json")
}

/// Try to load the catalog from an explicit URL first, then from GitHub release assets.
async fn fetch_extra_mods_catalog(config: &LauncherConfig) -> Result<(String, ExtraModsCatalog), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;

    if let Some(url) = config.extra_mods_catalog_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        let text = client.get(url).header("User-Agent", "GorizontLauncher/1.0").send().await
            .map_err(|e| format!("Не удалось скачать каталог модов: {e}"))?
            .error_for_status().map_err(|e| format!("Каталог модов недоступен: {e}"))?
            .text().await.map_err(|e| format!("Не удалось прочитать каталог модов: {e}"))?;
        let catalog = parse_extra_mods_catalog(&text)?;
        return Ok((url.to_string(), catalog));
    }

    let asset_name = config.extra_mods_catalog_asset.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("extra-mods.json");
    let releases_text = fetch_releases_text(config).await.map_err(|e| format!("Не удалось получить список релизов: {e}"))?;
    let releases: Vec<Release> = serde_json::from_str(&releases_text).map_err(|e| format!("Не удалось разобрать релизы: {e}"))?;
    let asset = releases.iter()
        .filter(|r| !r.draft)
        .find_map(|r| r.assets.iter().find(|a| a.name == asset_name).map(|a| a.browser_download_url.clone()));
    let Some(url) = asset else {
        return Err(format!("Каталог дополнительных модов не найден: в релизах GitHub нет файла {asset_name}"));
    };
    let text = client.get(&url).header("User-Agent", "GorizontLauncher/1.0").send().await
        .map_err(|e| format!("Не удалось скачать каталог модов: {e}"))?
        .error_for_status().map_err(|e| format!("Каталог модов недоступен: {e}"))?
        .text().await.map_err(|e| format!("Не удалось прочитать каталог модов: {e}"))?;
    let catalog = parse_extra_mods_catalog(&text)?;
    Ok((url, catalog))
}

/// Files that belong to the base modpack (paths relative to the game directory).
fn modpack_file_set(game_path: &Path) -> HashSet<String> {
    let mut files = HashSet::new();
    if let Ok(text) = fs::read_to_string(game_path.join(".gorizont-integrity.json")) {
        if let Ok(manifest) = serde_json::from_str::<FileIntegrityManifest>(&text) {
            for path in manifest.files.keys() { files.insert(path.replace('\\', "/")); }
        }
    }
    files
}

fn pack_mods_list_path(game_path: &Path) -> PathBuf {
    game_path.join(".gorizont-pack-mods.json")
}

fn save_pack_mod_list(game_path: &Path, names: &HashSet<String>) {
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();
    if let Ok(text) = serde_json::to_string_pretty(&sorted) { let _ = fs::write(pack_mods_list_path(game_path), text); }
}

/// File names of the mods that belong to the modpack. They are not "user mods": no approval applies to them and
/// the launcher does not list them.
fn pack_mod_filenames(game_path: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Ok(text) = fs::read_to_string(pack_mods_list_path(game_path)) {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&text) { names.extend(list); }
    }
    for path in modpack_file_set(game_path) {
        if let Some(name) = path.strip_prefix("mods/") { names.insert(name.to_string()); }
    }
    names
}

/// File names inside a zip on a web server, read from its central directory with one HTTP Range request
/// (the pack is hundreds of megabytes, only the last bytes are needed).
async fn remote_zip_names(url: &str) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().map_err(|e| e.to_string())?;
    // Some download servers answer 501 to suffix ranges ("bytes=-N"), so ask for the size first.
    let probe = client.get(url).header("User-Agent", "GorizontLauncher/1.0").header("Range", "bytes=0-0").send().await
        .map_err(|e| format!("запрос: {e}"))?;
    if probe.status().as_u16() != 206 { return Err(format!("сервер не поддерживает частичное чтение ({})", probe.status())); }
    let total: u64 = probe.headers().get(reqwest::header::CONTENT_RANGE).and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next()).and_then(|v| v.parse().ok()).ok_or("сервер не сообщил размер архива")?;
    let start = total.saturating_sub(262_144);
    let response = client.get(url).header("User-Agent", "GorizontLauncher/1.0").header("Range", format!("bytes={start}-{}", total - 1)).send().await
        .map_err(|e| format!("запрос: {e}"))?;
    if response.status().as_u16() != 206 { return Err(format!("сервер не поддерживает частичное чтение ({})", response.status())); }
    let tail = response.bytes().await.map_err(|e| e.to_string())?;
    let eocd = tail.windows(4).rposition(|w| w == [0x50, 0x4b, 0x05, 0x06]).ok_or("нет записи конца архива")?;
    if tail.len() < eocd + 22 { return Err("повреждённая запись конца архива".into()); }
    let cd_size = u32::from_le_bytes([tail[eocd + 12], tail[eocd + 13], tail[eocd + 14], tail[eocd + 15]]) as usize;
    if cd_size == 0 || cd_size > eocd { return Err("оглавление архива не поместилось в прочитанную часть".into()); }
    let directory = &tail[eocd - cd_size..eocd];
    let mut names = Vec::new();
    let mut i = 0usize;
    while i + 46 <= directory.len() && directory[i..i + 4] == [0x50, 0x4b, 0x01, 0x02] {
        let name_len = u16::from_le_bytes([directory[i + 28], directory[i + 29]]) as usize;
        let extra_len = u16::from_le_bytes([directory[i + 30], directory[i + 31]]) as usize;
        let comment_len = u16::from_le_bytes([directory[i + 32], directory[i + 33]]) as usize;
        if i + 46 + name_len > directory.len() { break; }
        names.push(String::from_utf8_lossy(&directory[i + 46..i + 46 + name_len]).replace('\\', "/"));
        i += 46 + name_len + extra_len + comment_len;
    }
    Ok(names)
}

/// Installs written before the pack list existed have no `.gorizont-pack-mods.json`: read the file list of the
/// installed pack release once from GitHub so its mods are not mistaken for user mods.
async fn ensure_pack_mods_list(game_path: &Path) {
    if pack_mods_list_path(game_path).exists() { return; }
    let Ok(text) = fs::read_to_string(game_path.join(".gorizont-installed.json")) else { return };
    let Ok(installed) = serde_json::from_str::<PackManifest>(&text) else { return };
    let Ok(config) = launcher_config() else { return };
    let Ok(releases_text) = fetch_releases_text(&config).await else { return };
    let Ok(releases) = serde_json::from_str::<Vec<Release>>(&releases_text) else { return };
    let wanted = installed.pack_version.trim_start_matches('v').to_string();
    let release = releases.iter().filter(|r| !r.draft)
        .find(|r| r.tag_name.trim_start_matches('v').trim_start_matches("pack-") == wanted && r.assets.iter().any(|a| a.name == config.modpack_asset));
    let Some(release) = release else { return };
    let Some(asset) = release.assets.iter().find(|a| a.name == config.modpack_asset) else { return };
    match remote_zip_names(&asset.browser_download_url).await {
        Ok(names) => {
            let mods: HashSet<String> = names.iter()
                .filter_map(|n| n.strip_prefix("mods/").map(|m| m.to_string()))
                .filter(|m| !m.is_empty() && !m.contains('/'))
                .collect();
            if !mods.is_empty() { save_pack_mod_list(game_path, &mods); }
        }
        Err(e) => eprintln!("[MODS] could not read the pack file list: {e}"),
    }
}

/// Names of approved user mods (they must survive modpack updates).
fn approved_user_mod_filenames(game_path: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Ok(manifest) = load_user_mods_manifest(game_path) {
        for m in manifest.mods.values() {
            if m.approved { names.insert(m.filename.clone()); }
        }
    }
    names
}

/// Get the path to the user mods manifest file
fn user_mods_manifest_path(game_path: &Path) -> PathBuf {
    game_path.join(".gorizont-user-mods.json")
}

/// Load user mods manifest from disk
fn load_user_mods_manifest(game_path: &Path) -> Result<UserModsManifest, String> {
    let path = user_mods_manifest_path(game_path);
    if !path.exists() {
        return Ok(UserModsManifest::default());
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("Failed to read user mods manifest: {}", e))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse user mods manifest: {}", e))
}

/// Save user mods manifest to disk
fn save_user_mods_manifest(game_path: &Path, manifest: &UserModsManifest) -> Result<(), String> {
    let path = user_mods_manifest_path(game_path);
    let text = serde_json::to_string_pretty(manifest).map_err(|e| format!("Failed to serialize user mods manifest: {}", e))?;
    fs::write(&path, text).map_err(|e| format!("Failed to write user mods manifest: {}", e))
}

/// Scan the mods directory for user-installed mods and update the manifest
fn scan_user_mods(game_path: &Path) -> Result<UserModsManifest, String> {
    enforce_blocked_mods(game_path);
    let mods_dir = game_path.join("mods");
    let mut manifest = load_user_mods_manifest(game_path)?;
    // Approval is decided by a moderator on the server. Without a cached list (never reached the server) the
    // previous local flag is kept so that nothing disappears just because the server is offline.
    let moderation = load_moderation_cache();
    let catalog_files: HashSet<String> = load_modrinth_state().installed.values().map(|i| i.filename.clone()).collect();
    let pack_mods = pack_mod_filenames(game_path);
    
    if !mods_dir.exists() {
        return Ok(manifest);
    }
    
    let entries = fs::read_dir(&mods_dir).map_err(|e| format!("Failed to read mods directory: {}", e))?;
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jar") {
            let filename = entry.file_name().to_string_lossy().to_string();
            if pack_mods.contains(&filename) { continue; }
            // Use filename without .jar as ID
            let id = filename.strip_suffix(".jar").unwrap_or(&filename).to_string();
            
            // Compute hash if not already in manifest or if file changed
            // Always re-hash: a jar swapped under an approved name must not inherit the approval.
            let should_update_hash = true;
            
            let hash = if should_update_hash {
                compute_file_sha256(&path)?
            } else {
                manifest.mods.get(&id).map(|m| m.hash.clone()).unwrap_or_default()
            };
            
            // Preserve existing enabled/approved state if mod already tracked
            let (enabled, approved, display_name, version) = if let Some(existing) = manifest.mods.get(&id) {
                (existing.enabled, existing.approved, existing.display_name.clone(), existing.version.clone())
            } else {
                (true, false, None, None)
            };
            let approved = match &moderation {
                Some(list) => list.approved.iter().any(|h| h.eq_ignore_ascii_case(&hash)),
                None => approved,
            } || catalog_files.contains(&filename);
            
            manifest.mods.insert(id.clone(), UserMod {
                id,
                filename: filename.clone(),
                hash,
                enabled,
                approved,
                display_name,
                version,
            });
        }
    }
    
    // Remove entries for mods that no longer exist in the directory
    let existing_ids: std::collections::HashSet<String> = fs::read_dir(&mods_dir)
        .map_err(|e| format!("Failed to read mods directory: {}", e))?
        .flatten()
        .filter(|e| e.path().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("jar"))
        .map(|e| e.file_name().to_string_lossy().strip_suffix(".jar").unwrap_or("").to_string())
        .collect();
    
    manifest.mods.retain(|id, m| existing_ids.contains(id) && !pack_mods.contains(&m.filename));
    
    save_user_mods_manifest(game_path, &manifest)?;
    Ok(manifest)
}

/// Get the path to the approved user mods backup directory
fn user_mods_backup_dir(game_path: &Path) -> PathBuf {
    game_path.join("mods-user-backup")
}

/// Backup approved user mods before modpack update
fn backup_approved_user_mods(game_path: &Path) -> Result<Vec<UserMod>, String> {
    let manifest = scan_user_mods(game_path)?;
    let backup_dir = user_mods_backup_dir(game_path);
    
    // Get approved and enabled mods
    let approved_mods: Vec<UserMod> = manifest.mods.values()
        .filter(|m| m.approved && m.enabled)
        .cloned()
        .collect();
    
    if approved_mods.is_empty() {
        return Ok(vec![]);
    }
    
    fs::create_dir_all(&backup_dir).map_err(|e| format!("Failed to create backup directory: {}", e))?;
    
    for mod_entry in &approved_mods {
        let src = game_path.join("mods").join(&mod_entry.filename);
        let dst = backup_dir.join(&mod_entry.filename);
        if src.exists() {
            fs::copy(&src, &dst).map_err(|e| format!("Failed to backup user mod {}: {}", mod_entry.filename, e))?;
        }
    }
    
    Ok(approved_mods)
}

/// Restore approved user mods after modpack update
fn restore_approved_user_mods(game_path: &Path, approved_mods: &[UserMod]) -> Result<(), String> {
    if approved_mods.is_empty() {
        return Ok(());
    }
    
    let backup_dir = user_mods_backup_dir(game_path);
    let mods_dir = game_path.join("mods");
    fs::create_dir_all(&mods_dir).map_err(|e| format!("Failed to create mods directory: {}", e))?;
    
    for mod_entry in approved_mods {
        let src = backup_dir.join(&mod_entry.filename);
        let dst = mods_dir.join(&mod_entry.filename);
        if src.exists() {
            fs::copy(&src, &dst).map_err(|e| format!("Failed to restore user mod {}: {}", mod_entry.filename, e))?;
        }
    }
    
    // Re-scan to update manifest with restored mods
    scan_user_mods(game_path)?;
    
    Ok(())
}

#[derive(Deserialize)]
struct VersionProfile {
    #[serde(rename = "mainClass")]
    main_class: Option<String>,
    assets: Option<String>,
    arguments: Option<LaunchArguments>,
    libraries: Option<Vec<LibraryEntry>>,
}

#[derive(Deserialize)]
struct LaunchArguments { jvm: Option<Vec<serde_json::Value>>, game: Option<Vec<serde_json::Value>> }

fn profile_values(values: &[serde_json::Value], replacements: &[(&str, String)]) -> Vec<String> {
    values.iter().flat_map(|value| {
        if let Some(text) = value.as_str() { return vec![text.to_string()]; }
        // Ignore arguments explicitly restricted to another operating system (for example macOS-only JVM flags).
        if let Some(rules) = value.get("rules").and_then(|rules| rules.as_array()) {
            // Feature-gated arguments (--demo, custom resolution, quick play) must not be passed unconditionally.
            if rules.iter().any(|rule| rule.get("features").is_some()) { return Vec::new(); }
            let allowed_for_windows = rules.iter().any(|rule| rule.get("action").and_then(|a| a.as_str()) == Some("allow") && rule.get("os").and_then(|os| os.get("name")).and_then(|name| name.as_str()).map(|name| name == "windows").unwrap_or(true));
            let restricted_elsewhere = rules.iter().any(|rule| rule.get("action").and_then(|a| a.as_str()) == Some("allow") && rule.get("os").and_then(|os| os.get("name")).and_then(|name| name.as_str()).map(|name| name != "windows").unwrap_or(false));
            if restricted_elsewhere && !allowed_for_windows { return Vec::new(); }
        }
        if let Some(text) = value.get("value").and_then(|v| v.as_str()) { return vec![text.to_string()]; }
        value.get("values").and_then(|items| items.as_array()).map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()).unwrap_or_default()
    }).map(|value| replacements.iter().fold(value, |text, (key, replacement)| text.replace(key, replacement))).collect()
}

#[derive(Deserialize)]
struct LibraryEntry { artifact: Option<LibraryArtifact>, downloads: Option<LibraryDownloads>, name: Option<String>, rules: Option<Vec<serde_json::Value>> }

#[derive(Deserialize)]
struct LibraryDownloads { artifact: Option<LibraryArtifact> }

#[derive(Deserialize)]
struct LibraryArtifact { path: String }

#[derive(Deserialize, Serialize)]
struct LoaderManifest {
    r#type: String,
    version: String,
}

fn launcher_config() -> Result<LauncherConfig, String> {
    serde_json::from_str(include_str!("../../launcher.config.json")).map_err(|e| format!("Ошибка launcher.config.json: {e}"))
}

#[derive(Deserialize, Debug)]
struct VersionOverride {
    #[serde(default)]
    minecraft_version: Option<String>,
    #[serde(default)]
    loader_type: Option<String>,
    #[serde(default)]
    loader_version: Option<String>,
}

fn releases_api_url(config: &LauncherConfig) -> String {
    format!("https://api.github.com/repos/{}/{}/releases?per_page=30", config.github_owner, config.github_repo)
}

struct ReleasesCache { etag: Option<String>, body: Option<String>, fetched: Option<std::time::Instant> }
static RELEASES_CACHE: std::sync::Mutex<ReleasesCache> = std::sync::Mutex::new(ReleasesCache { etag: None, body: None, fetched: None });

/// One shared GitHub releases request for the whole launcher. The answer is cached for 2 minutes and
/// revalidated with ETag (a 304 does not count against the unauthenticated 60 requests/hour limit).
/// If GitHub refuses (403/rate limit) or is unreachable, the last good answer is used.
async fn fetch_releases_text(config: &LauncherConfig) -> Result<String, String> {
    let (etag, cached) = {
        let cache = RELEASES_CACHE.lock().map_err(|_| "cache lock".to_string())?;
        if let (Some(body), Some(at)) = (&cache.body, cache.fetched) {
            if at.elapsed() < std::time::Duration::from_secs(120) { return Ok(body.clone()); }
        }
        (cache.etag.clone(), cache.body.clone())
    };
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let mut request = client.get(releases_api_url(config)).header("User-Agent", "GorizontLauncher/1.0").header("Accept", "application/vnd.github+json");
    if cached.is_some() { if let Some(tag) = &etag { request = request.header("If-None-Match", tag.as_str()); } }
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => return cached.ok_or_else(|| format!("запрос: {e}")),
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_MODIFIED {
        if let Some(body) = cached {
            if let Ok(mut cache) = RELEASES_CACHE.lock() { cache.fetched = Some(std::time::Instant::now()); }
            return Ok(body);
        }
    }
    if !status.is_success() { return cached.ok_or_else(|| format!("GitHub ответил {status}")); }
    let new_etag = response.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).map(String::from);
    let body = response.text().await.map_err(|e| format!("чтение ответа: {e}"))?;
    if let Ok(mut cache) = RELEASES_CACHE.lock() { cache.etag = new_etag; cache.body = Some(body.clone()); cache.fetched = Some(std::time::Instant::now()); }
    Ok(body)
}

/// Release list for the news panel (same cached request as the updater).
#[tauri::command]
async fn get_releases_json() -> Result<String, String> {
    let config = launcher_config()?;
    fetch_releases_text(&config).await
}

fn version_newer(candidate: &str, current: &str) -> bool {
    let parse = |version: &str| version.split('.').map(|part| part.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    let candidate = parse(candidate); let current = parse(current);
    for index in 0..candidate.len().max(current.len()) { let left = *candidate.get(index).unwrap_or(&0); let right = *current.get(index).unwrap_or(&0); if left != right { return left > right; } }
    false
}

/// Compute SHA256 hash of a file
fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("Failed to open file {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| format!("Failed to read file {}: {}", path.display(), e))?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Verify all files in the modpack against the integrity manifest
fn verify_integrity_manifest(
    game_path: &Path,
    manifest: &FileIntegrityManifest,
    config: &LauncherConfig,
) -> Result<(), String> {
    for (rel_path, expected_hash) in &manifest.files {
        let file_path = game_path.join(rel_path);
        if !file_path.exists() {
            // A mod the player disabled or removed on purpose is not corruption: skip it, do not reinstall the pack.
            if rel_path.replace('\\', "/").starts_with("mods/") { continue; }
            return Err(format!("File missing: {}", rel_path));
        }
        let actual_hash = compute_file_sha256(&file_path)?;
        if actual_hash.to_lowercase() != expected_hash.to_lowercase() {
            return Err(format!("File corrupted/modified: {} (expected {}, got {})", rel_path, expected_hash, actual_hash));
        }
    }
    // Also verify pack_version matches
    let marker = game_path.join(".gorizont-installed.json");
    if let Ok(text) = fs::read_to_string(&marker) {
        if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
            if installed.pack_version != manifest.pack_version {
                return Err(format!("Pack version mismatch: marker says {}, integrity manifest says {}", installed.pack_version, manifest.pack_version));
            }
        }
    }
    Ok(())
}

/// Download and parse the file integrity manifest from GitHub
async fn download_integrity_manifest(config: &LauncherConfig) -> Result<Option<FileIntegrityManifest>, String> {
    let Ok(releases_text) = fetch_releases_text(config).await else { return Ok(None) };
    let Ok(releases) = serde_json::from_str::<Vec<Release>>(&releases_text) else { return Ok(None) };
    
    for release in releases {
        if let Some(asset) = release.assets.iter().find(|a| a.name == "file-manifest.json") {
            let url = asset.browser_download_url.clone();
            let client = reqwest::Client::new();
            let response = match client.get(&url).header("User-Agent", "GorizontLauncher/1.0").send().await {
                Ok(r) => r,
                Err(_) => return Ok(None),
            };
            let response = match response.error_for_status() {
                Ok(r) => r,
                Err(_) => return Ok(None),
            };
            let manifest: FileIntegrityManifest = match response.json().await {
                Ok(m) => m,
                Err(_) => return Ok(None),
            };
            return Ok(Some(manifest));
        }
    }
    Ok(None)
}

#[derive(Clone, Serialize)] struct DownloadProgress { downloaded: u64, total: Option<u64>, percent: f32, stage: String }
#[derive(Deserialize)] struct Release { tag_name: String, #[serde(default)] draft: bool, assets: Vec<Asset> }
#[derive(Deserialize)] struct Asset { name: String, browser_download_url: String }
#[derive(Clone, Serialize)] struct LauncherUpdate { version: String, url: String, size: u64 }

fn validate_manifest(manifest: &PackManifest, config: &LauncherConfig) -> Result<(), String> {
    if manifest.schema_version != 1 { return Err(format!("Неподдерживаемая версия manifest.json: {}", manifest.schema_version)); }
    if manifest.pack_id != config.pack_id { return Err(format!("Неверная сборка: ожидался pack_id {}, получен {}", config.pack_id, manifest.pack_id)); }
    if manifest.minecraft_version.trim().is_empty() || manifest.loader.r#type.trim().is_empty() || manifest.loader.version.trim().is_empty() { return Err("В manifest.json не указан Minecraft или загрузчик".into()); }
    let _ = config;
    if manifest.pack_version.trim().is_empty() { return Err("В manifest.json отсутствует pack_version".into()); }
    Ok(())
}

fn emit_progress(app: &AppHandle, stage: &str, downloaded: u64, total: Option<u64>) {
    let percent = total.map(|t| if t > 0 { downloaded as f32 / t as f32 * 100.0 } else { 0.0 }).unwrap_or(0.0);
    let _ = app.emit("download-progress", DownloadProgress { downloaded, total, percent, stage: stage.to_string() });
}

/// After a modpack update, move mod jars that are no longer part of the pack into `mods-old`
/// so old and new versions of the same mod are never loaded together.
/// Jars that the user explicitly approved (or that were downloaded from the catalog) are kept.
fn retire_stale_mods<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>, target: &Path) {
    let mut keep = std::collections::HashSet::new();
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            if let Some(name) = file.enclosed_name() {
                if name.parent().map(|p| p == Path::new("mods")).unwrap_or(false) { if let Some(n) = name.file_name() { keep.insert(n.to_string_lossy().to_string()); } }
            }
        }
    }
    if keep.is_empty() { return; }
    save_pack_mod_list(target, &keep);
    let approved = approved_user_mod_filenames(target);
    let mods_dir = target.join("mods");
    let old_dir = target.join("mods-old");
    if let Ok(entries) = fs::read_dir(&mods_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_file() && name.to_lowercase().ends_with(".jar") && !keep.contains(&name) && !approved.contains(&name) {
                let _ = fs::create_dir_all(&old_dir);
                let _ = fs::rename(&path, old_dir.join(&name));
            }
        }
    }
}

fn safe_extract<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>, target: &Path, config: &LauncherConfig) -> Result<PackManifest, String> {
    if archive.len() > 20_000 { return Err("Архив содержит слишком много файлов".into()); }
    let mut manifest: Option<PackManifest> = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        let enclosed = file.enclosed_name().ok_or_else(|| "Небезопасный путь в архиве".to_string())?.to_owned();
        let file_name = enclosed.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name == config.expected_manifest {
            let mut text = String::new(); file.read_to_string(&mut text).map_err(|e| e.to_string())?;
            manifest = Some(serde_json::from_str(&text).map_err(|e| format!("Некорректный manifest.json: {e}"))?);
            continue;
        }
        let out = target.join(&enclosed);
        if file.is_dir() { fs::create_dir_all(&out).map_err(|e| e.to_string())?; continue; }
        if let Some(parent) = out.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        let mut output = fs::File::create(&out).map_err(|e| e.to_string())?;
        io::copy(&mut file, &mut output).map_err(|e| e.to_string())?;
    }
    let manifest = manifest.ok_or_else(|| format!("В архиве modpack.zip отсутствует {}", config.expected_manifest))?;
    retire_stale_mods(archive, target);
    validate_manifest(&manifest, config)?;
    Ok(manifest)
}

#[tauri::command]
async fn download_and_extract_modpack(app: AppHandle, url: String, target_dir: String, expected_sha256: Option<String>, signature_url: Option<String>) -> Result<(), String> {
    eprintln!("[DEBUG] download_and_extract_modpack called: url={}, target_dir={}", url, target_dir);
    let target = expand_windows_path(&target_dir); fs::create_dir_all(&target).map_err(|e| e.to_string())?; let config = launcher_config()?;
    
    // Backup approved user mods before extracting new modpack
    let approved_mods = backup_approved_user_mods(&target).unwrap_or_default();
    
    let response = reqwest::Client::new().get(&url).header("User-Agent", "GorizontLauncher/0.1").send().await.map_err(|e| e.to_string())?;
    let total = response.content_length(); let mut downloaded = 0; let mut bytes = Vec::new(); let mut stream = response.bytes_stream();
    emit_progress(&app, "Скачивание модов...", 0, total);
    while let Some(chunk) = stream.next().await { let chunk = chunk.map_err(|e| e.to_string())?; downloaded += chunk.len() as u64; bytes.extend_from_slice(&chunk); emit_progress(&app, "Скачивание модов...", downloaded, total); }
    if let Some(expected) = expected_sha256 { let actual = format!("{:x}", Sha256::digest(&bytes)); if actual.to_lowercase() != expected.to_lowercase() { return Err("Проверка SHA-256 не пройдена".into()); } }
    // Modpacks are installed only when their signature is valid.
    let signature_url = signature_url.ok_or_else(|| "В релизе нет подписи modpack.sig: сборка не будет установлена".to_string())?;
    let signature = reqwest::Client::new().get(&signature_url).header("User-Agent", "GorizontLauncher/1.0").send().await.and_then(|r| r.error_for_status()).map_err(|e| format!("Не удалось скачать подпись: {e}"))?.text().await.map_err(|e| e.to_string())?;
    verify_modpack_signature(&bytes, &signature)?;
    emit_progress(&app, "Распаковка модов...", 0, Some(bytes.len() as u64));
    let cursor = io::Cursor::new(bytes); let mut archive = ZipArchive::new(cursor).map_err(|e| e.to_string())?; let manifest = safe_extract(&mut archive, &target, &config)?;
    
    // Restore approved user mods after extracting new modpack
    if !approved_mods.is_empty() {
        emit_progress(&app, "Восстановление пользовательских модов...", 0, None);
        restore_approved_user_mods(&target, &approved_mods)?;
    }
    
    fs::write(target.join(".gorizont-installed.json"), serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    
    // Download and save integrity manifest for future verification
    if let Some(integrity_manifest) = download_integrity_manifest(&config).await? {
        fs::write(target.join(".gorizont-integrity.json"), serde_json::to_vec_pretty(&integrity_manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    
    emit_progress(&app, "Готово", 1, Some(1)); Ok(())
}

#[tauri::command]
async fn check_launcher_update() -> Result<Option<LauncherUpdate>, String> {
    let config = launcher_config()?;
    let releases: Vec<serde_json::Value> = serde_json::from_str(&fetch_releases_text(&config).await?).map_err(|e| e.to_string())?;
    let current = env!("CARGO_PKG_VERSION");
    for release in releases { let tag = release.get("tag_name").and_then(|v| v.as_str()).unwrap_or_default(); if !tag.starts_with("launcher-v") { continue; } let version = tag.trim_start_matches("launcher-v"); if !version_newer(version, current) { continue; } if let Some(asset) = release.get("assets").and_then(|v| v.as_array()).and_then(|assets| assets.iter().find(|a| a.get("name").and_then(|v| v.as_str()).map(|n| n.ends_with("-setup.exe")).unwrap_or(false))) { return Ok(Some(LauncherUpdate { version: version.into(), url: asset.get("browser_download_url").and_then(|v| v.as_str()).unwrap_or_default().into(), size: asset.get("size").and_then(|v| v.as_u64()).unwrap_or(0) })); } }
    Ok(None)
}

#[tauri::command]
async fn download_launcher_update(app: AppHandle, url: String) -> Result<(), String> {
    let response = reqwest::Client::new().get(&url).header("User-Agent", "GorizontLauncher/1.0").send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?;
    let total = response.content_length(); let mut downloaded = 0; let mut bytes = Vec::new(); let mut stream = response.bytes_stream(); emit_progress(&app, "Скачиваем обновление лаунчера...", 0, total);
    while let Some(chunk) = stream.next().await { let chunk = chunk.map_err(|e| e.to_string())?; downloaded += chunk.len() as u64; bytes.extend_from_slice(&chunk); emit_progress(&app, "Скачиваем обновление лаунчера...", downloaded, total); }
    let path = launcher_data_dir()?.join("GorizontLauncher-update.exe"); fs::write(&path, &bytes).map_err(|e| e.to_string())?;
    // Verify the installer file was written and has content
    let file_size = fs::metadata(&path).map_err(|e| e.to_string())?.len();
    if file_size == 0 {
        return Err("Скачанный установщик пуст".into());
    }
    emit_progress(&app, "Устанавливаем обновление поверх текущей версии...", 1, Some(1));
    // NSIS updates the existing installation in place; it is never an uninstall action.
    // Use detached process group so the installer survives after this launcher exits.
    let mut cmd = Command::new(&path);
    cmd.arg("/S");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000200 | 0x00000010); // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    }
    let mut child = cmd.spawn().map_err(|e| format!("Не удалось запустить установщик: {e}"))?;
    // Give the installer a moment to start and verify it's running
    thread::sleep(Duration::from_secs(2));
    // Check if the process is still alive (hasn't exited immediately with an error)
    match child.try_wait() {
        Ok(Some(status)) => {
            if !status.success() {
                return Err(format!("Установщик завершился с ошибкой (код: {})", status.code().unwrap_or(-1)));
            }
        }
        Ok(None) => {
            // Process is still running, good
        }
        Err(e) => {
            // Could not check process status, assume it's running
            eprintln!("[UPDATE] Could not verify installer process status: {}", e);
        }
    }
    app.exit(0); Ok(())
}

#[tauri::command]
async fn ensure_java(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(java_home) = env::var("JAVA_HOME") { let candidate = PathBuf::from(java_home).join("bin").join("javaw.exe"); if candidate.exists() { return Ok(candidate); } }
    if let Ok(path) = env::var("PATH") { for folder in path.split(';') { let candidate = PathBuf::from(folder).join("javaw.exe"); if candidate.exists() { return Ok(candidate); } } }
    let root = launcher_data_dir()?.join("runtime"); let java = root.join("bin").join("javaw.exe"); if java.exists() { return Ok(java); }
    fs::create_dir_all(&root).map_err(|e| e.to_string())?; emit_progress(app, "Скачиваем Java 21...", 0, None);
    let response = reqwest::Client::new().get(JAVA_DOWNLOAD_URL).header("User-Agent", "GorizontLauncher/1.0").send().await.map_err(|e| format!("Не удалось скачать Java 21: {e}"))?; let total = response.content_length(); let mut bytes = Vec::new(); let mut downloaded = 0; let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await { let chunk = chunk.map_err(|e| e.to_string())?; downloaded += chunk.len() as u64; bytes.extend_from_slice(&chunk); emit_progress(app, "Скачиваем Java 21...", downloaded, total); }
    let archive_path = launcher_data_dir()?.join("java.zip"); fs::write(&archive_path, bytes).map_err(|e| e.to_string())?; emit_progress(app, "Распаковываем Java 21...", 0, None);
    let file = fs::File::open(&archive_path).map_err(|e| e.to_string())?; let mut archive = ZipArchive::new(file).map_err(|e| format!("Архив Java повреждён: {e}"))?; let temp = launcher_data_dir()?.join("runtime-new"); if temp.exists() { fs::remove_dir_all(&temp).map_err(|e| e.to_string())?; } fs::create_dir_all(&temp).map_err(|e| e.to_string())?;
    for i in 0..archive.len() { let mut entry = archive.by_index(i).map_err(|e| e.to_string())?; let name = entry.enclosed_name().ok_or_else(|| "Небезопасный путь в архиве Java".to_string())?.to_owned(); let out = temp.join(name); if entry.is_dir() { fs::create_dir_all(out).map_err(|e| e.to_string())?; } else { if let Some(parent) = out.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; } let mut output = fs::File::create(out).map_err(|e| e.to_string())?; io::copy(&mut entry, &mut output).map_err(|e| e.to_string())?; } }
    let java_candidate = fs::read_dir(&temp).map_err(|e| e.to_string())?.filter_map(Result::ok).map(|e| e.path().join("bin").join("javaw.exe")).find(|p| p.exists()).ok_or_else(|| "В скачанном архиве Java не найден javaw.exe".to_string())?; if root.exists() { fs::remove_dir_all(&root).map_err(|e| e.to_string())?; } fs::rename(&temp, &root).map_err(|e| e.to_string())?; let _ = fs::remove_file(archive_path); Ok(root.join(java_candidate.strip_prefix(&temp).unwrap_or(Path::new("bin\\javaw.exe"))))
}

/// Latest published modpack version on GitHub (None when offline or no release has the pack asset).
async fn latest_pack_version(config: &LauncherConfig) -> Result<Option<String>, String> {
    let releases_text = fetch_releases_text(config).await?;
    let releases = serde_json::from_str::<Vec<Release>>(&releases_text).map_err(|e| format!("разбор ответа: {e}"))?;
    Ok(releases.into_iter().find(|r| r.assets.iter().any(|a| a.name == config.modpack_asset)).map(|release| release.tag_name.trim_start_matches('v').trim_start_matches("pack-").to_string()))
}

#[tauri::command]
async fn check_and_update_modpack(app: AppHandle, local_version: String, target_dir: String, version_override: Option<String>) -> Result<String, String> {
    let log_file = std::env::temp_dir().join("gorizont_launcher.log");
    let log = |msg: &str| {
        let _ = fs::OpenOptions::new().create(true).append(true).open(&log_file).and_then(|mut f| f.write_all(format!("[{}] {}\n", chrono::Local::now().format("%H:%M:%S%.3f"), msg).as_bytes()));
    };
    log(&format!("check_and_update_modpack called: local_version={}, target_dir={}", local_version, target_dir));
    eprintln!("check_and_update_modpack called: local_version={}, target_dir={}", local_version, target_dir);
    std::io::stderr().flush().ok();
    let emit = |stage: &str, downloaded: u64, total: Option<u64>| {
        emit_progress(&app, stage, downloaded, total);
    };
    emit("Проверка обновлений...", 0, None);
    let config = launcher_config()?;
    let override_opt: Option<VersionOverride> = version_override.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let effective_config = resolve_effective_config(&config, &override_opt);
    log(&format!("version_override={:?}", override_opt));
    log(&format!("effective config: mc={}, loader={}, loader_ver={}", effective_config.minecraft_version, effective_config.loader_type, effective_config.loader_version));
    log(&format!("local_modpack_path={:?}", effective_config.local_modpack_path));
    let target = expand_windows_path(&target_dir);
    log(&format!("target_dir expanded={:?}", target));
    let marker = target.join(".gorizont-installed.json");
    log(&format!("marker={:?}, exists={}", marker, marker.exists()));
    
    let version_id = pack_version_id(&target, &config);
    let profile_dir = target.join("versions").join(&version_id);
    let jar_exists = profile_dir.join(format!("{}.jar", version_id)).exists();
    let json_exists = profile_dir.join(format!("{}.json", version_id)).exists();
    let libs_dir = target.join("libraries");
    let libs_exist = libs_dir.exists() && libs_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    let mods_dir = target.join("mods");
    let mods_exist = mods_dir.exists() && mods_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    
    let mut force_update = false;
    // FIRST: Check if already installed with valid marker and correct version folder
    if let Ok(text) = fs::read_to_string(&marker) {
        log(&format!("marker read, installed version={:?}", text));
        if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
            log(&format!("manifest parsed: pack_version={}", installed.pack_version));
            if validate_manifest(&installed, &effective_config).is_ok() {
                log("manifest validation passed");
                {
                    match latest_pack_version(&effective_config).await {
                        Ok(Some(latest)) if version_newer(&latest, &installed.pack_version) => { log(&format!("newer pack on GitHub: {} > {}", latest, installed.pack_version)); force_update = true; }
                        other => {
                            if let Err(e) = &other { log(&format!("pack version check failed: {e}")); }
                            
                            if jar_exists && json_exists && libs_exist && mods_exist {
                                // Verify file integrity against GitHub manifest
                                emit("Проверка целостности файлов...", 0, None);
                                log("Verifying file integrity against GitHub manifest...");
                                if let Some(integrity_manifest) = download_integrity_manifest(&effective_config).await? {
                                    if let Err(e) = verify_integrity_manifest(&target, &integrity_manifest, &effective_config) {
                                        log(&format!("Integrity check FAILED: {}", e));
                                        emit("Файлы изменены, переустановка...", 0, None);
                                        force_update = true;
                                    } else {
                                        log("Integrity check PASSED");
                                        log("jar, json, libraries and mods exist and pack is up to date");
                                        return Ok(installed.pack_version);
                                    }
                                } else {
                                    log("No integrity manifest available on GitHub, skipping integrity check");
                                    log("jar, json, libraries and mods exist and pack is up to date");
                                    return Ok(installed.pack_version);
                                }
                            } else {
                                log(&format!("Missing files: jar={}, json={}, libs={}, mods={} - forcing update", jar_exists, json_exists, libs_exist, mods_exist));
                                force_update = true;
                            }
                        }
                    }
                }
            } else {
                log("manifest validation FAILED");
            }
        } else {
            log("failed to parse manifest JSON");
        }
    }
    
    // SECOND: If local_modpack_path is configured, use it as primary source
    if let Some(local_path) = &effective_config.local_modpack_path {
        let local_path = expand_windows_path(local_path);
        if local_path.exists() {
            log("Using local modpack as primary source");
            if !marker.exists() || !jar_exists || !json_exists || !libs_exist || !mods_exist {
                emit("Установка модпака...", 0, None);
                log("Installing from local modpack...");
                let bytes = fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?;
                log(&format!("Read modpack zip: {} bytes", bytes.len()));
                emit("Чтение архива модпака...", 0, None);
                let cursor = io::Cursor::new(bytes);
                let mut archive = ZipArchive::new(cursor).map_err(|e| format!("Некорректный ZIP архив: {e}"))?;
                log(&format!("Zip archive opened, {} files", archive.len()));
                log("safe_extract bypassed - reading manifest directly from zip...");
                // Read manifest.json directly from zip
                let manifest_name = effective_config.expected_manifest.clone();
                let mut manifest_text = String::new();
                let mut manifest_found = false;
                for i in 0..archive.len() {
                    let mut file = archive.by_index(i).map_err(|e| format!("Failed to read zip entry {}: {}", i, e))?;
                    if let Some(name) = file.enclosed_name() {
                        if name.to_string_lossy() == manifest_name {
                            file.read_to_string(&mut manifest_text).map_err(|e| format!("Failed to read manifest: {}", e))?;
                            manifest_found = true;
                            break;
                        }
                    }
                }
                if !manifest_found {
                    return Err(format!("manifest.json не найден в архиве"));
                }
                log(&format!("manifest.json read, length={}, content={:?}", manifest_text.len(), manifest_text));
                // Strip UTF-8 BOM if present
                let manifest_text = manifest_text.trim_start_matches('\u{feff}');
                // Fix double-quoted keys like ""schema_version"" -> "schema_version"
                // Only replace ""key"" -> "key" when it appears before a colon (JSON key)
                let manifest_text = {
                    let mut result = String::new();
                    let mut i = 0;
                    let chars: Vec<char> = manifest_text.chars().collect();
                    while i < chars.len() {
                        if chars[i] == '"' && i + 1 < chars.len() && chars[i + 1] == '"' {
                            // Found double quote - check if this looks like a doubled key
                            // Look ahead to find the closing "" and then a colon
                            let mut j = i + 2;
                            let mut found_closing = false;
                            while j + 1 < chars.len() {
                                if chars[j] == '"' && chars[j + 1] == '"' {
                                    found_closing = true;
                                    break;
                                }
                                j += 1;
                            }
                            if found_closing {
                                // Check if after the closing "" there's a colon (possibly with whitespace)
                                let mut k = j + 2;
                                while k < chars.len() && chars[k].is_whitespace() {
                                    k += 1;
                                }
                                if k < chars.len() && chars[k] == ':' {
                                    // This is a doubled key - write single quotes
                                    result.push('"');
                                    i += 2; // skip the opening ""
                                    while i < j {
                                        result.push(chars[i]);
                                        i += 1;
                                    }
                                    result.push('"');
                                    i = j + 2; // skip the closing ""
                                    continue;
                                }
                            }
                        }
                        result.push(chars[i]);
                        i += 1;
                    }
                    result
                };
                log(&format!("manifest after BOM/quote fix: {:?}", manifest_text));
                let manifest_result: Result<PackManifest, _> = serde_json::from_str(&manifest_text);
                let manifest = match manifest_result {
                    Ok(m) => {
                        log(&format!("manifest parsed OK: pack_id={}, pack_version={}, loader={} {}", m.pack_id, m.pack_version, m.loader.r#type, m.loader.version));
                        m
                    }
                    Err(e) => {
                        log(&format!("serde_json::from_str FAILED: {}", e));
                        return Err(format!("Некорректный manifest.json: {}", e));
                    }
                };
                validate_manifest(&manifest, &effective_config)?;
                log("manifest validation passed");
                
                // Backup approved user mods before extracting new modpack
                let approved_mods = backup_approved_user_mods(&target).unwrap_or_default();
                if !approved_mods.is_empty() {
                    emit("Резервное копирование пользовательских модов...", 0, None);
                    log(&format!("Backed up {} approved user mods", approved_mods.len()));
                }
                
                // Extract all files from zip
                emit("Распаковка модпака...", 0, None);
                log("Extracting all files from zip...");
                // Reset cursor to beginning for re-reading
                let cursor2 = io::Cursor::new(fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?);
                let mut archive2 = ZipArchive::new(cursor2).map_err(|e| format!("Некорректный ZIP архив: {}", e))?;
                let total_files = archive2.len() as u64;
                for i in 0..archive2.len() {
                    let mut file = archive2.by_index(i).map_err(|e| e.to_string())?;
                    let enclosed = file.enclosed_name().ok_or_else(|| "Небезопасный путь в архиве".to_string())?.to_owned();
                    let out = target.join(&enclosed);
                    if file.is_dir() {
                        fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                        continue;
                    }
                    if let Some(parent) = out.parent() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    let mut output = fs::File::create(&out).map_err(|e| e.to_string())?;
                    io::copy(&mut file, &mut output).map_err(|e| e.to_string())?;
                    if i % 50 == 0 {
                        emit("Распаковка модпака...", i as u64, Some(total_files));
                    }
                }
                emit("Распаковка завершена", total_files, Some(total_files));
                log("All files extracted");
                
                // Remove stale mods that are no longer in the pack first, so restored user mods
                // are not swept away with the old pack files.
                let cursor3 = io::Cursor::new(fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?);
                let mut archive3 = ZipArchive::new(cursor3).map_err(|e| format!("Некорректный ZIP архив: {}", e))?;
                retire_stale_mods(&mut archive3, &target);
                log("Stale mods retired");

                // Restore approved user mods after the pack is extracted and cleaned up
                if !approved_mods.is_empty() {
                    emit("Восстановление пользовательских модов...", 0, None);
                    log("Restoring approved user mods...");
                    restore_approved_user_mods(&target, &approved_mods)?;
                }
                
                // Ensure libraries, mods and config exist (copy from default .minecraft if missing)
                if let Err(e) = ensure_assets(&target) {
                    log(&format!("Warning: {}", e));
                }
                
                // Fix: modpack.zip contains old folder name "Create(VOID)", rename to expected version_id
                let old_profile_dir = target.join("versions").join("Create(VOID)");
                let new_profile_dir = target.join("versions").join(&version_id);
                log(&format!("After extract: old_profile_dir exists={}, new_profile_dir exists={}", old_profile_dir.exists(), new_profile_dir.exists()));
                if old_profile_dir.exists() && !new_profile_dir.exists() {
                    log(&format!("Renaming version folder: Create(VOID) -> {}", version_id));
                    fs::rename(&old_profile_dir, &new_profile_dir).map_err(|e| format!("Не удалось переименовать папку версии: {e}"))?;
                    let old_jar = new_profile_dir.join("Create(VOID).jar");
                    let new_jar = new_profile_dir.join(format!("{}.jar", version_id));
                    log(&format!("Renaming jar: {} -> {} (exists={})", old_jar.display(), new_jar.display(), old_jar.exists()));
                    if old_jar.exists() { fs::rename(&old_jar, &new_jar).map_err(|e| log(&format!("jar rename failed: {}", e))).ok(); }
                    let old_json = new_profile_dir.join("Create(VOID).json");
                    let new_json = new_profile_dir.join(format!("{}.json", version_id));
                    log(&format!("Renaming json: {} -> {} (exists={})", old_json.display(), new_json.display(), old_json.exists()));
                    if old_json.exists() { fs::rename(&old_json, &new_json).map_err(|e| log(&format!("json rename failed: {}", e))).ok(); }
                }
                
                // Verify final state
                let final_jar = new_profile_dir.join(format!("{}.jar", version_id));
                let final_json = new_profile_dir.join(format!("{}.json", version_id));
                log(&format!("Final check: jar_exists={}, json_exists={}", final_jar.exists(), final_json.exists()));
                
                // Write updated marker with correct version from manifest
                let installed_version = manifest.pack_version.clone();
                fs::write(target.join(".gorizont-installed.json"), serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                
                // Download and save integrity manifest for future verification
                if let Some(integrity_manifest) = download_integrity_manifest(&effective_config).await? {
                    fs::write(target.join(".gorizont-integrity.json"), serde_json::to_vec_pretty(&integrity_manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                }
                
                emit("Готово", 1, Some(1));
                log(&format!("Local modpack installed, version={}", installed_version));
                return Ok(installed_version);
            } else {
                log("Local modpack already installed, verifying integrity...");
                // Verify integrity for already installed local modpack
                if let Some(integrity_manifest) = download_integrity_manifest(&effective_config).await? {
                    if let Err(e) = verify_integrity_manifest(&target, &integrity_manifest, &effective_config) {
                        log(&format!("Integrity check FAILED for local modpack: {}", e));
                        force_update = true;
                    } else {
                        log("Integrity check PASSED for local modpack");
                        if let Ok(text) = fs::read_to_string(&marker) {
                            if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
                                return Ok(installed.pack_version);
                            }
                        }
                        return Ok("local".to_string());
                    }
                } else {
                    log("No integrity manifest available on GitHub, skipping integrity check");
                    if let Ok(text) = fs::read_to_string(&marker) {
                        if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
                            return Ok(installed.pack_version);
                        }
                    }
                    return Ok("local".to_string());
                }
            }
        }
    }
    
    // THIRD: Fallback to GitHub releases (only if no local modpack configured)
    if let Ok(releases_text) = fetch_releases_text(&effective_config).await {
        {
            if let Ok(releases) = serde_json::from_str::<Vec<Release>>(&releases_text) {
                if let Some(release) = releases.into_iter().find(|r| r.assets.iter().any(|a| a.name == effective_config.modpack_asset)) {
                    let latest = release.tag_name.trim_start_matches('v').trim_start_matches("pack-").to_string();
                    let asset_url = release.assets.iter().find(|a| a.name == effective_config.modpack_asset).map(|a| a.browser_download_url.clone());
                    let signature_url = release.assets.iter().find(|a| a.name == "modpack.sig").map(|a| a.browser_download_url.clone());
                    log(&format!("GitHub fallback: latest={}, local_version={}", latest, local_version));
                    if let Some(asset_url) = asset_url {
                        if force_update || latest != local_version.trim_start_matches('v') || !marker.exists() {
                            emit("Скачивание модпака с GitHub...", 0, None);
                            log("Downloading from GitHub...");
                            download_and_extract_modpack(app, asset_url, target_dir, None, signature_url).await?;
                            return Ok(latest);
                        }
                        return Ok(latest);
                    }
                }
            }
        }
    }
    
    log("No modpack source available");
    Err("Не найден модпак: не настроен локальный путь и нет релиза на GitHub".into())
}

fn library_allowed(library: &serde_json::Value) -> bool {
    if let Some(name) = library.get("name").and_then(|n| n.as_str()) { if name.ends_with("natives-windows-arm64") || name.ends_with("natives-windows-x86") { return false; } }
    match library.get("rules").and_then(|r| r.as_array()) {
        Some(rules) => rules.iter().any(|rule| rule.get("action").and_then(|a| a.as_str()) == Some("allow") && rule.get("os").and_then(|os| os.get("name")).and_then(|n| n.as_str()).map(|n| n == "windows").unwrap_or(true)),
        None => true,
    }
}

async fn fetch_to(client: &reqwest::Client, urls: &[String], dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let mut last = String::from("нет адресов для загрузки");
    for url in urls {
        match client.get(url).header("User-Agent", "GorizontLauncher/1.0").send().await.and_then(|r| r.error_for_status()) {
            Ok(response) => match response.bytes().await {
                Ok(bytes) => { let tmp = dest.with_extension("part"); fs::write(&tmp, &bytes).map_err(|e| e.to_string())?; fs::rename(&tmp, dest).map_err(|e| e.to_string())?; return Ok(()); }
                Err(e) => last = format!("{url}: {e}"),
            },
            Err(e) => last = format!("{url}: {e}"),
        }
    }
    Err(last)
}

/// Downloads libraries and assets that the version profile needs but are missing on disk (fresh installs).
async fn ensure_game_files(app: &AppHandle, game_path: &Path, version_id: &str) -> Result<(), String> {
    let profile_path = game_path.join("versions").join(version_id).join(format!("{version_id}.json"));
    let profile: serde_json::Value = serde_json::from_str(&fs::read_to_string(&profile_path).map_err(|e| format!("Не найден профиль Minecraft: {e}"))?).map_err(|e| format!("Профиль Minecraft повреждён: {e}"))?;
    let client = reqwest::Client::new();

    // Libraries
    let mut jobs: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for library in profile.get("libraries").and_then(|l| l.as_array()).cloned().unwrap_or_default() {
        if !library_allowed(&library) { continue; }
        let Some(artifact) = library.get("artifact").or_else(|| library.get("downloads").and_then(|d| d.get("artifact"))) else { continue };
        let Some(path) = artifact.get("path").and_then(|p| p.as_str()) else { continue };
        let relative = path.trim_start_matches("libraries/");
        let dest = game_path.join("libraries").join(relative);
        let alt = game_path.join(path);
        if dest.exists() || alt.exists() { continue; }
        let mut urls = Vec::new();
        if let Some(url) = artifact.get("url").and_then(|u| u.as_str()) { if !url.is_empty() { urls.push(url.replace("http://", "https://")); } }
        urls.push(format!("https://libraries.minecraft.net/{relative}"));
        urls.push(format!("https://maven.neoforged.net/releases/{relative}"));
        urls.push(format!("https://repo1.maven.org/maven2/{relative}"));
        jobs.push((dest, urls));
    }
    let total = jobs.len() as u64;
    if total > 0 {
        emit_progress(app, "Скачивание библиотек...", 0, Some(total));
        let done = std::sync::atomic::AtomicU64::new(0);
        let results: Vec<Result<(), String>> = futures_util::stream::iter(jobs).map(|(dest, urls)| { let client = client.clone(); let done = &done; async move {
            let r = fetch_to(&client, &urls, &dest).await;
            let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            emit_progress(app, "Скачивание библиотек...", n, Some(total));
            r
        } }).buffer_unordered(8).collect().await;
        if let Some(Err(e)) = results.into_iter().find(|r| r.is_err()) { return Err(format!("Не удалось скачать библиотеку: {e}")); }
    }

    // Assets
    if let Some(index) = profile.get("assetIndex") {
        let id = index.get("id").and_then(|v| v.as_str()).unwrap_or("legacy");
        let index_path = game_path.join("assets").join("indexes").join(format!("{id}.json"));
        if !index_path.exists() {
            if let Some(url) = index.get("url").and_then(|u| u.as_str()) { fetch_to(&client, &[url.to_string()], &index_path).await.map_err(|e| format!("Не удалось скачать индекс ресурсов: {e}"))?; }
        }
        if let Ok(text) = fs::read_to_string(&index_path) {
            if let Ok(index_json) = serde_json::from_str::<serde_json::Value>(&text) {
                let mut jobs: Vec<(PathBuf, Vec<String>)> = Vec::new();
                for (_, object) in index_json.get("objects").and_then(|o| o.as_object()).cloned().unwrap_or_default() {
                    let Some(hash) = object.get("hash").and_then(|h| h.as_str()) else { continue };
                    if hash.len() < 2 { continue; }
                    let dest = game_path.join("assets").join("objects").join(&hash[..2]).join(hash);
                    if dest.exists() { continue; }
                    jobs.push((dest, vec![format!("https://resources.download.minecraft.net/{}/{}", &hash[..2], hash)]));
                }
                let total = jobs.len() as u64;
                if total > 0 {
                    emit_progress(app, "Скачивание ресурсов игры...", 0, Some(total));
                    let done = std::sync::atomic::AtomicU64::new(0);
                    let results: Vec<Result<(), String>> = futures_util::stream::iter(jobs).map(|(dest, urls)| { let client = client.clone(); let done = &done; async move {
                        let r = fetch_to(&client, &urls, &dest).await;
                        let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if n % 25 == 0 || n == total { emit_progress(app, "Скачивание ресурсов игры...", n, Some(total)); }
                        r
                    } }).buffer_unordered(24).collect().await;
                    let failed = results.iter().filter(|r| r.is_err()).count();
                    if failed > 0 { eprintln!("[ASSETS] {failed} asset files failed to download"); }
                }
            }
        }
    }
    Ok(())
}

struct LoaderInfo { mc: String, kind: String, version: String }

/// Loader described by the installed pack's manifest (falls back to launcher.config.json before the first install).
fn read_installed_loader(game_path: &Path, config: &LauncherConfig) -> LoaderInfo {
    if let Ok(text) = fs::read_to_string(game_path.join(".gorizont-installed.json")) {
        if let Ok(m) = serde_json::from_str::<PackManifest>(&text) { return LoaderInfo { mc: m.minecraft_version, kind: m.loader.r#type, version: m.loader.version }; }
    }
    // No installed pack yet: the loader is unknown until the pack's manifest.json is downloaded.
    LoaderInfo { mc: config.minecraft_version.clone(), kind: config.loader_type.clone(), version: config.loader_version.clone() }
}
fn loader_version_id(l: &LoaderInfo) -> String { if l.version.is_empty() { String::new() } else { format!("{}-{}-{}", l.mc, l.kind, l.version) } }
fn pack_version_id(game_path: &Path, config: &LauncherConfig) -> String { loader_version_id(&read_installed_loader(game_path, config)) }

/// Full NeoForge version for a manifest value: "266" + Minecraft 1.21.1 -> "21.1.266"; values with dots are used as is.
fn neoforge_full_version(l: &LoaderInfo) -> String {
    if l.version.contains('.') { return l.version.clone(); }
    let parts: Vec<&str> = l.mc.split('.').collect();
    format!("{}.{}.{}", parts.get(1).unwrap_or(&"0"), parts.get(2).unwrap_or(&"0"), l.version)
}

/// Installs the loader named in the pack manifest (NeoForge via its official installer) and writes a
/// self-contained version profile `versions/<mc>-<loader>-<version>/`.
async fn ensure_loader(app: &AppHandle, game_path: &Path, info: &LoaderInfo) -> Result<(), String> {
    let version_id = loader_version_id(info);
    if version_id.is_empty() { return Err("Сборка ещё не установлена: загрузчик указывается в manifest.json модпака".into()); }
    let dir = game_path.join("versions").join(&version_id);
    let json_path = dir.join(format!("{version_id}.json"));
    let jar_path = dir.join(format!("{version_id}.jar"));
    if json_path.exists() && jar_path.exists() { return Ok(()); }
    if info.kind != "neoforge" { return Err(format!("Загрузчик «{}» пока не поддерживается лаунчером", info.kind)); }
    let full = neoforge_full_version(info);
    let log_path = game_path.join("launcher-loader.log");
    let client = reqwest::Client::new();

    let installer = launcher_data_dir()?.join("loaders").join(format!("neoforge-{full}-installer.jar"));
    if !installer.exists() {
        emit_progress(app, "Скачивание загрузчика NeoForge...", 0, None);
        let url = format!("https://maven.neoforged.net/releases/net/neoforged/neoforge/{full}/neoforge-{full}-installer.jar");
        fetch_to(&client, &[url], &installer).await.map_err(|e| format!("Не удалось скачать NeoForge {full}: {e}"))?;
    }

    emit_progress(app, "Установка загрузчика NeoForge (может занять несколько минут)...", 0, None);
    fs::create_dir_all(game_path).map_err(|e| e.to_string())?;
    let profiles = game_path.join("launcher_profiles.json");
    if !profiles.exists() { fs::write(&profiles, "{\"profiles\":{},\"version\":3}").map_err(|e| e.to_string())?; }
    let javaw = ensure_java(app).await?;
    let java = { let exe = javaw.with_file_name("java.exe"); if exe.exists() { exe } else { javaw } };
    let (installer_c, game_c, log_c) = (installer.clone(), game_path.to_path_buf(), log_path.clone());
    let status = tauri::async_runtime::spawn_blocking(move || {
        let log_file = fs::File::create(&log_c).map_err(|e| e.to_string())?;
        let log_err = log_file.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new(java);
        cmd.arg("-jar").arg(&installer_c).arg("--installClient").arg(&game_c).stdout(std::process::Stdio::from(log_file)).stderr(std::process::Stdio::from(log_err));
        #[cfg(windows)]
        { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
        cmd.status().map_err(|e| format!("Не удалось запустить установщик NeoForge: {e}"))
    }).await.map_err(|e| e.to_string())??;
    if !status.success() {
        let tail = fs::read_to_string(&log_path).unwrap_or_default().lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        return Err(format!("Установщик NeoForge завершился с ошибкой. Подробности в launcher-loader.log\n{tail}"));
    }

    // Merge the NeoForge profile with its vanilla parent into one standalone profile.
    let neo_id = format!("neoforge-{full}");
    let child: serde_json::Value = serde_json::from_str(&fs::read_to_string(game_path.join("versions").join(&neo_id).join(format!("{neo_id}.json"))).map_err(|e| format!("Профиль NeoForge не найден после установки: {e}"))?).map_err(|e| e.to_string())?;
    let parent_id = child.get("inheritsFrom").and_then(|v| v.as_str()).unwrap_or(&info.mc).to_string();
    let parent: serde_json::Value = serde_json::from_str(&fs::read_to_string(game_path.join("versions").join(&parent_id).join(format!("{parent_id}.json"))).map_err(|e| format!("Профиль Minecraft {parent_id} не найден: {e}"))?).map_err(|e| e.to_string())?;
    let mut merged = parent.clone();
    let mut seen = std::collections::HashSet::new();
    let mut libs = Vec::new();
    for lib in child.get("libraries").and_then(|l| l.as_array()).into_iter().flatten().chain(parent.get("libraries").and_then(|l| l.as_array()).into_iter().flatten()) {
        let key = lib.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string();
        if key.is_empty() || seen.insert(key) { libs.push(lib.clone()); }
    }
    merged["libraries"] = serde_json::Value::Array(libs);
    let arg_list = |v: &serde_json::Value, k: &str| -> Vec<serde_json::Value> { v.get("arguments").and_then(|a| a.get(k)).and_then(|a| a.as_array()).cloned().unwrap_or_default() };
    let jvm: Vec<_> = arg_list(&parent, "jvm").into_iter().chain(arg_list(&child, "jvm")).collect();
    let game: Vec<_> = arg_list(&parent, "game").into_iter().chain(arg_list(&child, "game")).collect();
    merged["arguments"] = serde_json::json!({ "jvm": jvm, "game": game });
    if let Some(main) = child.get("mainClass") { merged["mainClass"] = main.clone(); }
    if let Some(obj) = merged.as_object_mut() { obj.remove("inheritsFrom"); }
    merged["id"] = serde_json::Value::String(version_id.clone());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(&json_path, serde_json::to_vec_pretty(&merged).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    fs::copy(game_path.join("versions").join(&parent_id).join(format!("{parent_id}.jar")), &jar_path).map_err(|e| format!("Не удалось подготовить клиент Minecraft: {e}"))?;
    emit_progress(app, "Загрузчик NeoForge установлен", 1, Some(1));
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemMemory { total_mb: u64, available_mb: u64 }

#[repr(C)]
struct MemoryStatusEx { length: u32, memory_load: u32, total_phys: u64, avail_phys: u64, total_page_file: u64, avail_page_file: u64, total_virtual: u64, avail_virtual: u64, avail_extended_virtual: u64 }

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" { fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32; }

fn read_system_memory() -> Option<SystemMemory> {
    #[cfg(windows)]
    {
        let mut status = MemoryStatusEx { length: std::mem::size_of::<MemoryStatusEx>() as u32, memory_load: 0, total_phys: 0, avail_phys: 0, total_page_file: 0, avail_page_file: 0, total_virtual: 0, avail_virtual: 0, avail_extended_virtual: 0 };
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 { return Some(SystemMemory { total_mb: status.total_phys / 1024 / 1024, available_mb: status.avail_phys / 1024 / 1024 }); }
    }
    None
}

/// Information about a detected Java installation.
#[derive(Debug, Clone)]
struct JavaInfo {
    major_version: u32,
    is_64bit: bool,
}

/// Run `java -XshowSettings:properties -version` and parse version + architecture.
fn detect_java_info(java_path: &Path) -> Result<JavaInfo, String> {
    let output = Command::new(java_path)
        .arg("-XshowSettings:properties")
        .arg("-version")
        .output()
        .map_err(|e| format!("Не удалось запустить java -version: {e}"))?;
    let output_str = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr).to_string();

    let mut major_version: Option<u32> = None;
    let mut is_64bit: Option<bool> = None;

    for line in output_str.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("java.version = ") {
            let v: Option<u32> = rest.split('.').next()
                .and_then(|s| s.parse().ok())
                .or_else(|| rest.split('_').next().and_then(|s| s.parse().ok()));
            major_version = v;
        } else if let Some(rest) = line.strip_prefix("sun.arch.data.model = ") {
            is_64bit = Some(rest.trim() == "64");
        } else if let Some(rest) = line.strip_prefix("os.arch = ") {
            if is_64bit.is_none() {
                is_64bit = Some(rest.contains("64") || rest == "amd64" || rest == "aarch64");
            }
        }
    }

    let major = major_version.ok_or_else(|| "Не удалось определить версию Java".to_string())?;
    Ok(JavaInfo { major_version: major, is_64bit: is_64bit.unwrap_or(false) })
}

/// Required Java major version for a given Minecraft version:
/// 1.16.5 and below → Java 8; 1.17–1.20.4 → Java 17; 1.20.5+ → Java 21.
fn required_java_for_mc(mc_version: &str) -> u32 {
    let parts: Vec<&str> = mc_version.split('.').collect();
    let major: u32 = parts.get(0).and_then(|p| p.parse().ok()).unwrap_or(1);
    let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

    if major == 1 && minor <= 16 {
        return 8;
    }
    if major == 1 && minor == 20 && patch >= 5 {
        return 21;
    }
    if major == 1 && minor >= 17 && minor <= 20 {
        return 17;
    }
    if major > 1 || minor > 20 {
        return 21;
    }
    17
}

/// Remove JVM flags that don't exist on older Java versions.
fn filter_jvm_args(args: &[String], java_info: &JavaInfo, _required_java: u32) -> Vec<String> {
    let mut filtered = Vec::new();
    for arg in args {
        let lower = arg.to_lowercase();

        // Java 8 doesn't know --add-opens / --add-exports / --add-modules
        if java_info.major_version < 9 {
            if lower.starts_with("--add-opens") || lower.starts_with("--add-exports") || lower.starts_with("--add-modules") {
                continue;
            }
            // ZGC / Shenandoah / Epsilon don't exist on Java 8
            if lower.contains("-XX:+UseZGC") || lower.contains("-XX:+UseShenandoahGC")
                || lower.contains("-XX:+UseEpsilonGC") {
                continue;
            }
        }

        filtered.push(arg.clone());
    }
    filtered
}

/// Escape a Windows command argument: quote if it contains spaces or double-quotes.
/// Backslashes in Windows paths are normal and do NOT need quoting.
fn escape_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "".to_string();
    }
    let needs_quote = arg.contains(' ') || arg.contains('"');
    if !needs_quote {
        return arg.to_string();
    }
    let escaped = arg.replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

/// Clamp RAM considering Java bitness: 32-bit Java can't use more than ~1500 MB.
fn clamp_ram_for_java(requested: u32, java_info: &JavaInfo) -> u32 {
    let system_max = read_system_memory()
        .map(|m| (m.total_mb.saturating_sub(2048)).max(2048) as u32)
        .unwrap_or(8192);
    let mut max = system_max.min(8192);
    if !java_info.is_64bit {
        max = max.min(1400); // 32-bit JVM: stay well under 2 GB limit
    }
    requested.clamp(256, max)
}

/// Read the tail of a log file (last N lines) for error diagnostics.
fn read_log_tail(log_path: &Path, lines: usize) -> String {
    fs::read_to_string(log_path)
        .ok()
        .and_then(|content| {
            let mut lines_vec: Vec<&str> = content.lines().collect();
            let selected = if lines_vec.len() > lines {
                lines_vec.split_off(lines_vec.len() - lines)
            } else {
                lines_vec
            };
            Some(selected.join("\n"))
        })
        .unwrap_or_else(|| "<не удалось прочитать лог>".to_string())
}

#[tauri::command]
fn get_system_memory() -> Result<SystemMemory, String> { read_system_memory().ok_or_else(|| "Не удалось определить объём ОЗУ".to_string()) }

#[tauri::command]
async fn prepare_game_files(app: AppHandle, game_dir: String, version_override: Option<String>) -> Result<(), String> {
    let config = launcher_config()?;
    let override_opt: Option<VersionOverride> = version_override.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let effective_config = resolve_effective_config(&config, &override_opt);
    let game_path = expand_windows_path(&game_dir);
    let _ = refresh_moderation().await;
    enforce_blocked_mods(&game_path);
    let loader = read_installed_loader(&game_path, &effective_config);
    let version_id = loader_version_id(&loader);
    if let Err(e) = ensure_assets(&game_path) { eprintln!("[PREPARE] ensure_assets failed: {e}"); }

    // Verify file integrity before launching
    let marker = game_path.join(".gorizont-installed.json");
    if marker.exists() {
        if let Some(integrity_manifest) = download_integrity_manifest(&effective_config).await? {
            if let Err(e) = verify_integrity_manifest(&game_path, &integrity_manifest, &effective_config) {
                eprintln!("[PREPARE] Integrity check FAILED: {}", e);
                return Err(format!("Файлы игры изменены или повреждены: {}. Требуется переустановка.", e));
            } else {
                eprintln!("[PREPARE] Integrity check PASSED");
            }
        }
    }

    if !version_id.is_empty() { ensure_loader(&app, &game_path, &loader).await?; }
    ensure_game_files(&app, &game_path, &version_id).await
}

#[tauri::command]
async fn launch_minecraft(app: AppHandle, username: String, ram_mb: u32, game_dir: String, java_path: Option<String>, launcher_jar: Option<String>, version_override: Option<String>, access_token: Option<String>) -> Result<(), String> {
    eprintln!("[LAUNCH] launch_minecraft called: username={}, ram_mb={}, game_dir={}", username, ram_mb, game_dir);
    if username.trim().is_empty() { return Err("Введите ник".into()); }
    if let Err(e) = ensure_assets(&expand_windows_path(&game_dir)) { eprintln!("[LAUNCH] ensure_assets failed: {e}"); }
    let config = launcher_config()?;
    let override_opt: Option<VersionOverride> = version_override.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let effective_config = resolve_effective_config(&config, &override_opt);
    let game_path = expand_windows_path(&game_dir);
    let version_id = pack_version_id(&game_path, &effective_config);
    eprintln!("[LAUNCH] game_path={:?}, version_id={}", game_path, version_id);
    let jar = launcher_jar.map(|p| expand_windows_path(&p)).unwrap_or_else(|| game_path.join("versions").join(&version_id).join(format!("{version_id}.jar")));
    eprintln!("[LAUNCH] jar path: {:?}, exists={}", jar, jar.exists());
    if !jar.exists() { return Err(format!("Файл Minecraft не найден: {}. Сначала добавьте modpack.zip с клиентом или укажите правильную папку игры.", jar.display())); }

    // Verify file integrity before launching
    let marker = game_path.join(".gorizont-installed.json");
    if marker.exists() {
        if let Some(integrity_manifest) = download_integrity_manifest(&effective_config).await? {
            if let Err(e) = verify_integrity_manifest(&game_path, &integrity_manifest, &effective_config) {
                eprintln!("[LAUNCH] Integrity check FAILED: {}", e);
                return Err(format!("Файлы игры изменены или повреждены: {}. Требуется переустановка через лаунчер.", e));
            } else {
                eprintln!("[LAUNCH] Integrity check PASSED");
            }
        }
    }

    // --- Java detection: version + architecture ---
    let java = match java_path.filter(|p| !p.trim().is_empty()) {
        Some(path) => expand_windows_path(&path),
        None => ensure_java(&app).await?,
    };
    eprintln!("[LAUNCH] java path: {:?}", java);
    let java_info = detect_java_info(&java)?;
    eprintln!("[LAUNCH] Java {} (64bit={})", java_info.major_version, java_info.is_64bit);

    // --- Required Java for this Minecraft version ---
    let mc_version = effective_config.minecraft_version.as_str();
    let required_java = required_java_for_mc(mc_version);
    if java_info.major_version < required_java {
        return Err(format!(
            "Для Minecraft {} требуется Java {}, а установлена Java {}. Обновите Java.",
            mc_version, required_java, java_info.major_version
        ));
    }

    // --- RAM limit: 32-bit Java capped at ~1400 MB ---
    let ram = clamp_ram_for_java(ram_mb, &java_info);
    eprintln!("[LAUNCH] RAM: {} MB (32bit={})", ram, java_info.is_64bit);

    let server = format!("{}:{}", effective_config.server_address, effective_config.server_port);
    let profile_text = fs::read_to_string(game_path.join("versions").join(&version_id).join(format!("{version_id}.json"))).map_err(|e| format!("Не найден профиль Minecraft {version_id}: {e}"))?;
    let profile: VersionProfile = serde_json::from_str(&profile_text).map_err(|e| format!("Профиль Minecraft повреждён: {e}"))?;
    let libraries = profile.libraries.unwrap_or_default().into_iter().filter(|library| {
        // Skip libraries restricted to other operating systems/architectures.
        if let Some(name) = &library.name { if name.ends_with("natives-windows-arm64") || name.ends_with("natives-windows-x86") { return false; } }
        match &library.rules {
            Some(rules) => rules.iter().any(|rule| rule.get("action").and_then(|a| a.as_str()) == Some("allow") && rule.get("os").and_then(|os| os.get("name")).and_then(|n| n.as_str()).map(|n| n == "windows").unwrap_or(true)),
            None => true,
        }
    }).filter_map(|library| library.artifact.or(library.downloads.and_then(|d| d.artifact)).map(|a| {
        // Some profiles (TLauncher) store paths with a "libraries/" prefix, others without it.
        let direct = game_path.join(&a.path);
        if direct.exists() { direct } else { game_path.join("libraries").join(&a.path) }
    })).filter(|path| path.exists()).map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>();
    let assets_index = profile.assets.clone().unwrap_or_else(|| config.minecraft_version.clone());
    // Escape each classpath entry for paths with spaces/Cyrillic, then join with ;
    let cp_entries: Vec<String> = libraries.into_iter().chain(std::iter::once(jar.to_string_lossy().to_string())).map(|p| escape_windows_arg(&p)).collect();
    let classpath = cp_entries.join(";");
    let access_token_value = access_token.unwrap_or_else(|| "0".to_string());
    let uuid_value = "00000000000000000000000000000000".to_string();
    let replacements = [("${auth_player_name}", username.clone()), ("${version_name}", version_id.clone()), ("${game_directory}", game_path.to_string_lossy().to_string()), ("${assets_root}", game_path.join("assets").to_string_lossy().to_string()), ("${assets_index_name}", assets_index.clone()), ("${auth_access_token}", access_token_value), ("${auth_uuid}", uuid_value), ("${auth_xuid}", "".into()), ("${clientid}", "".into()), ("${launcher_name}", "GorizontLauncher".into()), ("${launcher_version}", env!("CARGO_PKG_VERSION").into()), ("${classpath}", classpath.clone()), ("${natives_directory}", escape_windows_arg(&game_path.join("versions").join(&version_id).join("natives").to_string_lossy().to_string())), ("${library_directory}", escape_windows_arg(&game_path.join("libraries").to_string_lossy().to_string())), ("${classpath_separator}", ";".into()), ("${user_type}", "mojang".into()), ("${version_type}", "release".into()), ("${resolution_width}", "854".into()), ("${resolution_height}", "480".into()), ("${quickPlayPath}", "".into()), ("${quickPlaySingleplayer}", "false".into()), ("${quickPlayMultiplayer}", "false".into()), ("${quickPlayRealms}", "false".into())];
    let LaunchArguments { jvm, game } = profile.arguments.unwrap_or(LaunchArguments { jvm: None, game: None });
    let mut args = vec![format!("-Xmx{ram}M"), format!("-Xms{}M", ram.min(2048))];
    if let Some(jvm) = jvm {
        let mut jvm_args = profile_values(&jvm, &replacements);
        jvm_args = filter_jvm_args(&jvm_args, &java_info, required_java);
        args.extend(jvm_args);
    }
    args.extend(["-cp".into(), classpath, profile.main_class.unwrap_or_else(|| "cpw.mods.bootstraplauncher.BootstrapLauncher".into())]);
    if let Some(game) = game { args.extend(profile_values(&game, &replacements)); }
    args.extend(["--server".into(), effective_config.server_address.clone(), "--port".into(), effective_config.server_port.to_string()]);

    // --- Log the full command line before spawning ---
    let java_log_path = game_path.join("launcher-java.log");
    // Write command to log, then open in append mode for Java's stdout/stderr
    {
        let mut f = fs::File::create(&java_log_path).map_err(|e| format!("Не удалось создать лог Java: {e}"))?;
        let _ = writeln!(f, "=== Gorizont Launcher Java command ===");
        let _ = writeln!(f, "Java: {}", java.display());
        for arg in &args {
            let _ = writeln!(f, "{}", escape_windows_arg(arg));
        }
        let _ = writeln!(f, "=====================================");
    }
    eprintln!("[LAUNCH] spawning java with {} args", args.len());

    // Make sure the Gorizont server is in the multiplayer list.
    match servers::ensure_default_server(&game_path, "Gorizont", &server) { Ok(changed) => eprintln!("[LAUNCH] servers.dat updated={changed}"), Err(e) => eprintln!("[LAUNCH] servers.dat error: {e}") }

    // Spawn Java with captured stderr, cleared _JAVA_OPTIONS, and escaped paths.
    let java_log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&java_log_path)
        .map_err(|e| format!("Не удалось создать лог Java: {e}"))?;
    let java_err = java_log.try_clone().map_err(|e| e.to_string())?;
    let mut child = Command::new(&java)
        .args(args.iter().map(|a| a.as_str()))
        .current_dir(&game_path)
        .env("GORIZONT_SERVER", &server)
        .env_remove("_JAVA_OPTIONS")
        .stdout(Stdio::from(java_log.try_clone().unwrap_or(java_log)))
        .stderr(Stdio::from(java_err))
        .spawn()
        .map_err(|e| format!("Не удалось запустить Java: {e}"))?;
    eprintln!("[LAUNCH] Java spawned successfully (pid={:?})", child.id());

    // Hide the launcher while Minecraft is running and bring it back when the game exits.
    let window = app.get_webview_window("main");
    if let Some(w) = &window { let _ = w.hide(); }
    let log_path_clone = java_log_path.clone();
    std::thread::spawn(move || {
        let status = child.wait();
        // Read the tail of the log for any JVM error messages.
        let tail = read_log_tail(&log_path_clone, 20);
        eprintln!("[LAUNCH] Minecraft exited: {:?}", status);
        if !status.map(|s| s.success()).unwrap_or(false) {
            eprintln!("[LAUNCH] Java stderr tail:\n{}", tail);
        }
        if let Some(w) = window { let _ = w.show(); let _ = w.unminimize(); let _ = w.set_focus(); }
        let _ = app.emit("minecraft-exited", ());
    });
    Ok(())
}

#[derive(Serialize)]
struct MojangProfile { id: String, name: String }

/// Looks a nickname up in Mojang's database. Returns None when no licensed account has this name.
#[tauri::command]
async fn lookup_mojang_profile(username: String) -> Result<Option<MojangProfile>, String> {
    let name = username.trim();
    if name.len() < 3 || name.len() > 16 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') { return Ok(None); }
    let response = reqwest::Client::new().get(format!("https://api.mojang.com/users/profiles/minecraft/{name}")).header("User-Agent", "GorizontLauncher/1.0").send().await.map_err(|e| e.to_string())?;
    if response.status() == reqwest::StatusCode::NOT_FOUND || response.status() == reqwest::StatusCode::NO_CONTENT { return Ok(None); }
    let value: serde_json::Value = response.error_for_status().map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    Ok(match (value.get("id").and_then(|v| v.as_str()), value.get("name").and_then(|v| v.as_str())) { (Some(id), Some(name)) => Some(MojangProfile { id: id.into(), name: name.into() }), _ => None })
}

#[tauri::command]
async fn link_ip_to_account(username: String) -> Result<(), String> {
    let url = webhook_url();
    let token = webhook_token();
    if url.is_empty() || token.is_empty() { return Err("Веб-хук не настроен в конфигурации лаунчера".into()); }
    Client::new().post(url).bearer_auth(token).json(&serde_json::json!({"username": username})).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?; Ok(())
}

#[tauri::command]
async fn auth_login(
    pool: State<'_, DbPool>,
    active: State<'_, ActiveAccountState>,
    request: LoginRequest,
) -> Result<AuthResponse, String> {
    // The game server is the source of truth for accounts; fall back to the local
    // mirror only when the server is unreachable or no shared key is configured.
    if server_hmac_secret().is_some() {
        match server_auth_login(request.nickname.clone(), request.password.clone()).await {
            Ok(reply) => match reply.status.as_str() {
                "ok" => {}
                "invalid_password" => return Err("Неверный пароль".into()),
                "not_found" => return Err("Пользователь не найден".into()),
                "invalid_input" => return Err("Некорректный ник или пароль".into()),
                "locked" => return Err(reply.error.clone().unwrap_or_else(|| "Слишком много неудачных попыток, попробуйте позже".into())),
                other => return Err(reply.error.clone().unwrap_or_else(|| format!("Сервер авторизации: {other}"))),
            },
            Err(e) => eprintln!("[AUTH] Server login unavailable, using local account: {e}"),
        }
    }
    let response = local_login_or_mirror(&pool, &request.nickname, &request.password, &request.device_fp).await?;
    remember_active_account(&active, &response);
    Ok(response)
}

#[tauri::command]
async fn auth_register(
    pool: State<'_, DbPool>,
    active: State<'_, ActiveAccountState>,
    request: RegisterRequest,
) -> Result<AuthResponse, String> {
    if server_hmac_secret().is_some() {
        match server_auth_register(request.nickname.clone(), request.password.clone()).await {
            Ok(reply) => match reply.status.as_str() {
                "registered" => {}
                "already_exists" => return Err("Этот ник уже зарегистрирован — используйте вход".into()),
                "invalid_input" => return Err("Некорректный ник или слишком короткий пароль".into()),
                other => return Err(format!("Сервер авторизации: {other}")),
            },
            Err(e) => eprintln!("[AUTH] Server registration unavailable, using local account: {e}"),
        }
    }
    // Mirror the account locally so the launcher can still issue tokens offline.
    let response = match auth::register_user(&pool, &request.nickname, &request.password, &request.device_fp).await {
        Ok(response) => response,
        Err(_) => local_login_or_mirror(&pool, &request.nickname, &request.password, &request.device_fp).await?,
    };
    remember_active_account(&active, &response);
    Ok(response)
}

#[tauri::command]
async fn auth_refresh(
    pool: State<'_, DbPool>,
    active: State<'_, ActiveAccountState>,
    request: RefreshRequest,
) -> Result<AuthResponse, String> {
    let response = auth::refresh_tokens(&pool, &request.refresh_token, &request.device_fp).await?;
    remember_active_account(&active, &response);
    Ok(response)
}

#[tauri::command]
async fn auth_logout(
    pool: State<'_, DbPool>,
    active: State<'_, ActiveAccountState>,
    request: LogoutRequest,
) -> Result<(), String> {
    let result = auth::logout_user(&pool, &request.refresh_token).await;
    if result.is_ok() {
        let mut guard = active.write().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }
    result
}

#[tauri::command]
async fn auth_me(
    pool: State<'_, DbPool>,
    access_token: String,
) -> Result<auth::UserResponse, String> {
    auth::get_user_profile(&pool, &access_token).await
}

#[tauri::command]
async fn auth_forgot_password(
    pool: State<'_, DbPool>,
    request: ForgotPasswordRequest,
) -> Result<(), String> {
    auth::forgot_password(&pool, &request.nickname).await
}

#[tauri::command]
async fn auth_oauth(
    pool: State<'_, DbPool>,
    request: OAuthRequest,
) -> Result<AuthResponse, String> {
    auth::oauth_login(
        &pool,
        &request.provider,
        &request.code,
        &request.code,
        None,
        None,
        &request.device_fp,
    ).await
}

/// Scan user-installed mods in the mods directory
#[tauri::command]
async fn scan_user_mods_cmd(game_dir: String) -> Result<UserModsManifest, String> {
    let game_path = expand_windows_path(&game_dir);
    ensure_pack_mods_list(&game_path).await;
    let _ = refresh_moderation().await;
    scan_user_mods(&game_path)
}

/// Get user mods manifest
#[tauri::command]
async fn get_user_mods(game_dir: String) -> Result<UserModsManifest, String> {
    let game_path = expand_windows_path(&game_dir);
    ensure_pack_mods_list(&game_path).await;
    let mut manifest = load_user_mods_manifest(&game_path)?;
    let pack_mods = pack_mod_filenames(&game_path);
    manifest.mods.retain(|_, m| !pack_mods.contains(&m.filename));
    Ok(manifest)
}

/// Toggle user mod enabled/disabled state
#[tauri::command]
async fn toggle_user_mod(game_dir: String, mod_id: String, enabled: bool) -> Result<UserModsManifest, String> {
    let game_path = expand_windows_path(&game_dir);
    let mut manifest = load_user_mods_manifest(&game_path)?;
    
    if let Some(mod_entry) = manifest.mods.get_mut(&mod_id) {
        mod_entry.enabled = enabled;
        save_user_mods_manifest(&game_path, &manifest)?;
    } else {
        return Err(format!("Mod not found: {}", mod_id));
    }
    
    Ok(manifest)
}

/// Toggle user mod approved state (for persistence across updates)
#[tauri::command]
async fn approve_user_mod(game_dir: String, mod_id: String, approved: bool) -> Result<UserModsManifest, String> {
    // Approval belongs to the moderator and is stored on the server (see moderate_mod); a local request
    // cannot grant it. This only re-reads the files and the server-wide list.
    let _ = approved;
    let _ = refresh_moderation().await;
    let game_path = expand_windows_path(&game_dir);
    ensure_pack_mods_list(&game_path).await;
    let manifest = scan_user_mods(&game_path)?;
    if !manifest.mods.contains_key(&mod_id) {
        return Err(format!("Mod not found: {}", mod_id));
    }
    Ok(manifest)
}

/// Remove a user mod from tracking (but keep the file)
#[tauri::command]
async fn remove_user_mod_tracking(game_dir: String, mod_id: String) -> Result<UserModsManifest, String> {
    let game_path = expand_windows_path(&game_dir);
    let mut manifest = load_user_mods_manifest(&game_path)?;
    
    manifest.mods.remove(&mod_id);
    save_user_mods_manifest(&game_path, &manifest)?;
    
    Ok(manifest)
}

/// Backup approved user mods before modpack update
#[tauri::command]
async fn backup_user_mods(game_dir: String) -> Result<Vec<UserMod>, String> {
    let game_path = expand_windows_path(&game_dir);
    backup_approved_user_mods(&game_path)
}

/// Restore approved user mods after modpack update
#[tauri::command]
async fn restore_user_mods(game_dir: String, approved_mods: Vec<UserMod>) -> Result<(), String> {
    let game_path = expand_windows_path(&game_dir);
    restore_approved_user_mods(&game_path, &approved_mods)
}

/// Build the UI list: catalog entries plus their local installation state.
fn build_extra_mods_states(game_path: &Path, catalog: &ExtraModsCatalog) -> Vec<ExtraModState> {
    let pack_files = modpack_file_set(game_path);
    let mods_dir = game_path.join("mods");
    catalog.mods.iter().map(|spec| {
        let target = mods_dir.join(&spec.filename);
        let in_modpack = pack_files.contains(&format!("mods/{}", spec.filename));
        let mut installed = false;
        let mut outdated = false;
        if target.exists() {
            match (&spec.sha256, compute_file_sha256(&target)) {
                (Some(expected), Ok(actual)) if actual.eq_ignore_ascii_case(expected.trim()) => installed = true,
                (Some(_), _) => outdated = true,
                (None, _) => installed = true,
            }
        }
        ExtraModState {
            id: spec.id.clone(),
            name: spec.name.clone(),
            version: spec.version.clone(),
            description: spec.description.clone(),
            filename: spec.filename.clone(),
            url: spec.url.clone(),
            sha256: spec.sha256.clone(),
            size: spec.size,
            minecraft_version: spec.minecraft_version.clone(),
            loader: spec.loader.clone(),
            installed,
            outdated,
            in_modpack,
        }
    }).collect()
}

/// Return the additional mods catalog with installation status for the given game directory.
#[tauri::command]
async fn get_extra_mods_catalog(game_dir: Option<String>) -> Result<ExtraModsResponse, String> {
    let config = launcher_config()?;
    let game_path = game_dir.as_deref().map(expand_windows_path);
    match fetch_extra_mods_catalog(&config).await {
        Ok((source, catalog)) => {
            if let Some(ref path) = game_path {
                if let Ok(text) = serde_json::to_string_pretty(&catalog) {
                    let _ = fs::write(extra_mods_cache_path(path), text);
                }
            }
            let mods = match &game_path { Some(p) => build_extra_mods_states(p, &catalog), None => catalog.mods.iter().map(|spec| ExtraModState {
                id: spec.id.clone(), name: spec.name.clone(), version: spec.version.clone(), description: spec.description.clone(),
                filename: spec.filename.clone(), url: spec.url.clone(), sha256: spec.sha256.clone(), size: spec.size,
                minecraft_version: spec.minecraft_version.clone(), loader: spec.loader.clone(),
                installed: false, outdated: false, in_modpack: false,
            }).collect() };
            Ok(ExtraModsResponse { source, mods, error: None })
        }
        Err(error) => {
            // Fall back to the cached catalog so the section is not empty offline.
            if let Some(ref path) = game_path {
                if let Ok(text) = fs::read_to_string(extra_mods_cache_path(path)) {
                    if let Ok(catalog) = parse_extra_mods_catalog(&text) {
                        let mods = build_extra_mods_states(path, &catalog);
                        return Ok(ExtraModsResponse { source: "cache".into(), mods, error: Some(error) });
                    }
                }
            }
            Ok(ExtraModsResponse { source: String::new(), mods: Vec::new(), error: Some(error) })
        }
    }
}

/// Download one additional mod into the game `mods/` directory.
/// - verifies SHA256 from the catalog when it is present
/// - never overwrites a file that belongs to the base modpack
/// - refuses to overwrite a different local file unless `overwrite` is true
/// - registers the file as an approved user mod so modpack updates keep it
#[tauri::command]
async fn download_extra_mod(app: AppHandle, game_dir: String, spec: ExtraModSpec, overwrite: bool) -> Result<ExtraModState, String> {
    // Reject separators and parent references before touching the file system.
    if !spec.filename.to_lowercase().ends_with(".jar") { return Err("Дополнительный мод должен быть .jar".into()); }
    let single_segment = Path::new(&spec.filename).components().count() == 1;
    if !single_segment || spec.filename.contains("..") { return Err("Недопустимое имя файла мода".into()); }
    if !spec.url.to_lowercase().starts_with("https://") { return Err("Ссылка на мод должна быть https".into()); }

    let game_path = expand_windows_path(&game_dir);
    let mods_dir = game_path.join("mods");
    fs::create_dir_all(&mods_dir).map_err(|e| format!("Не удалось создать папку mods: {e}"))?;
    let target = mods_dir.join(&spec.filename);
    let state_for_spec = |game_path: &Path| -> ExtraModState {
        build_extra_mods_states(game_path, &ExtraModsCatalog { schema_version: 1, mods: vec![spec.clone()] })
            .into_iter().next().expect("state for one mod")
    };

    // The launcher must never touch files that belong to the base modpack.
    if modpack_file_set(&game_path).contains(&format!("mods/{}", spec.filename)) {
        return Err(format!("Файл {} входит в сборку — лаунчер не перезаписывает моды сборки", spec.filename));
    }

    let expected = spec.sha256.as_deref().map(str::trim).filter(|h| !h.is_empty()).map(str::to_string);
    if let Some(ref expected_hash) = expected {
        if expected_hash.len() != 64 || !expected_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Некорректный SHA-256 в каталоге для {}", spec.filename));
        }
    }

    if target.exists() {
        let actual = compute_file_sha256(&target)?;
        let same = match &expected {
            Some(expected_hash) => actual.eq_ignore_ascii_case(expected_hash),
            None => true,
        };
        if same { return Ok(state_for_spec(&game_path)); }
        if !overwrite {
            return Err(format!("Файл {} уже существует и отличается по хешу. Подтвердите перезапись.", spec.filename));
        }
    }

    emit_progress(&app, &format!("Скачивание мода {}...", spec.name), 0, spec.size);
    let response = reqwest::Client::new().get(&spec.url).header("User-Agent", "GorizontLauncher/1.0").send().await
        .map_err(|e| format!("Не удалось скачать {}: {e}", spec.name))?;
    let response = response.error_for_status().map_err(|e| format!("Не удалось скачать {}: {e}", spec.name))?;
    let total = response.content_length().or(spec.size.filter(|s| *s > 0));
    let mut downloaded = 0u64;
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Ошибка загрузки {}: {e}", spec.name))?;
        downloaded += chunk.len() as u64;
        bytes.extend_from_slice(&chunk);
        emit_progress(&app, &format!("Скачивание мода {}...", spec.name), downloaded, total);
    }
    if bytes.is_empty() { return Err(format!("Скачанный файл {} пуст", spec.name)); }
    let actual_hash = format!("{:x}", Sha256::digest(&bytes));
    if let Some(ref expected_hash) = expected {
        if !actual_hash.eq_ignore_ascii_case(expected_hash) {
            return Err(format!("Проверка SHA-256 не пройдена для {}: ожидался {expected_hash}, получен {actual_hash}", spec.name));
        }
    }

    emit_progress(&app, &format!("Установка мода {}...", spec.name), downloaded, total);
    let tmp = target.with_extension("jar.part");
    fs::write(&tmp, &bytes).map_err(|e| format!("Не удалось записать {}: {e}", spec.filename))?;
    if target.exists() { fs::remove_file(&target).map_err(|e| format!("Не удалось заменить {}: {e}", spec.filename))?; }
    fs::rename(&tmp, &target).map_err(|e| format!("Не удалось установить {}: {e}", spec.filename))?;

    // Register as an approved user mod so modpack updates keep the file.
    let mut manifest = load_user_mods_manifest(&game_path)?;
    let mod_id = spec.filename.strip_suffix(".jar").unwrap_or(&spec.filename).to_string();
    manifest.mods.insert(mod_id.clone(), UserMod {
        id: mod_id,
        filename: spec.filename.clone(),
        hash: actual_hash,
        enabled: true,
        approved: true,
        display_name: Some(spec.name.clone()),
        version: spec.version.clone(),
    });
    save_user_mods_manifest(&game_path, &manifest)?;

    emit_progress(&app, "Готово", 1, Some(1));
    Ok(state_for_spec(&game_path))
}

// ===================== Modrinth integration =====================

const MODRINTH_API: &str = "https://api.modrinth.com/v2";
const MODRINTH_UA: &str = "GorizontLauncher/1.0 (github.com/YaroslavPetrushenko/GorizontLauncher)";

/// Raw project row returned by the Modrinth search endpoint.
#[derive(Deserialize, Clone, Debug)]
struct ModrinthHitRaw {
    project_id: String,
    slug: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    author: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default, rename = "client_side")]
    client_side: String,
    #[serde(default, rename = "server_side")]
    server_side: String,
    #[serde(default)]
    downloads: u64,
    #[serde(default)]
    follows: u64,
    #[serde(default, rename = "icon_url")]
    icon_url: Option<String>,
    #[serde(default, rename = "date_modified")]
    date_modified: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ModrinthSearchRaw {
    #[serde(default)]
    hits: Vec<ModrinthHitRaw>,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    limit: u32,
    #[serde(default)]
    total_hits: u32,
}

/// A search hit as the UI consumes it (camelCase fields).
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ModrinthHit {
    project_id: String,
    slug: String,
    title: String,
    description: String,
    author: String,
    icon_url: Option<String>,
    downloads: u64,
    follows: u64,
    categories: Vec<String>,
    client_side: String,
    server_side: String,
    date_modified: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ModrinthSearchResponse {
    hits: Vec<ModrinthHit>,
    total_hits: u32,
    offset: u32,
    limit: u32,
}


#[derive(Deserialize, Clone, Debug)]
struct ModrinthHashes {
    #[serde(default)]
    sha512: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct ModrinthFile {
    #[serde(default)]
    url: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    hashes: Option<ModrinthHashes>,
}

#[derive(Deserialize, Clone, Debug)]
struct ModrinthVersion {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version_number: String,
    #[serde(default)]
    files: Vec<ModrinthFile>,
}

/// What the launcher remembers about Modrinth mods: blocked projects and installed ones.
#[derive(Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct ModrinthState {
    #[serde(default)]
    blocked: Vec<String>,
    #[serde(default)]
    installed: HashMap<String, InstalledProject>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct InstalledProject {
    filename: String,
    #[serde(default)]
    version_number: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ExtraModsState {
    installed: Vec<String>,
    blocked: Vec<String>,
    titles: HashMap<String, String>,
}

fn modrinth_state_path() -> Result<PathBuf, String> {
    Ok(launcher_data_dir()?.join("modrinth-state.json"))
}

fn load_modrinth_state() -> ModrinthState {
    match modrinth_state_path().ok().and_then(|p| fs::read_to_string(p).ok()) {
        Some(text) => serde_json::from_str(&text).unwrap_or_default(),
        None => ModrinthState::default(),
    }
}

fn save_modrinth_state(state: &ModrinthState) -> Result<(), String> {
    let path = modrinth_state_path()?;
    let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fs::write(&path, text).map_err(|e| format!("Не удалось сохранить состояние модов: {e}"))
}

fn modrinth_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))
}

/// Facets restrict the search to client mods for this pack (Minecraft version + loader).
fn modrinth_facets(game_version: &str, loader: &str, categories: &[String]) -> serde_json::Value {
    let mut facets: Vec<Vec<String>> = vec![
        vec!["project_type:mod".to_string()],
        vec![format!("versions:{game_version}")],
        vec![format!("categories:{loader}")],
        // Client mods only: they must work on the client and must not need to be on the server.
        vec![
            "client_side:required".to_string(),
            "client_side:optional".to_string(),
        ],
        vec![
            "server_side:unsupported".to_string(),
            "server_side:optional".to_string(),
        ],
    ];
    let cats: Vec<String> = categories.iter()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .map(|c| format!("categories:{c}"))
        .collect();
    if !cats.is_empty() {
        facets.push(cats);
    }
    serde_json::Value::Array(facets.into_iter().map(|group| {
        serde_json::Value::Array(group.into_iter().map(serde_json::Value::String).collect())
    }).collect())
}

/// Resolve the pack's Minecraft version and loader.
fn pack_game_version(game_version: Option<String>) -> Result<(String, String), String> {
    let config = launcher_config()?;
    let version = game_version.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or(config.minecraft_version);
    Ok((version, config.loader_type))
}

/// Search Modrinth for client mods matching this pack.
/// Blocked projects are filtered out on the backend, so the UI never sees them.
#[tauri::command]
async fn modrinth_search(
    query: Option<String>,
    game_version: Option<String>,
    loader: Option<String>,
    categories: Option<Vec<String>>,
    index: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<ModrinthSearchResponse, String> {
    let (mc_version, config_loader) = pack_game_version(game_version)?;
    let project_loader = loader.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).unwrap_or(config_loader);
    let client = modrinth_client()?;
    let facets = modrinth_facets(&mc_version, &project_loader, &categories.unwrap_or_default());
    let offset = offset.unwrap_or(0).min(900);
    let limit = limit.unwrap_or(20).clamp(1, 50);
    let index = match index.as_deref() {
        Some("downloads") => "downloads",
        Some("newest") => "newest",
        _ => "relevance",
    };
    let query_text = query.unwrap_or_default();
    let offset_text = offset.to_string();
    let limit_text = limit.to_string();
    let facets_text = facets.to_string();
    let response = client
        .get(format!("{MODRINTH_API}/search"))
        .header("User-Agent", MODRINTH_UA)
        .query(&[
            ("query", query_text.as_str()),
            ("index", index),
            ("offset", offset_text.as_str()),
            ("limit", limit_text.as_str()),
            ("facets", facets_text.as_str()),
        ])
        .send().await
        .map_err(|e| format!("Modrinth недоступен: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Modrinth вернул ошибку: {e}"))?;
    let raw: ModrinthSearchRaw = response.json().await.map_err(|e| format!("Не удалось разобрать ответ Modrinth: {e}"))?;

    let state = load_modrinth_state();
    let hits: Vec<ModrinthHit> = raw.hits.into_iter()
        .filter(|h| !state.blocked.iter().any(|b| b == &h.project_id))
        .map(|h| ModrinthHit {
            project_id: h.project_id,
            slug: h.slug,
            title: h.title,
            description: h.description,
            author: h.author,
            icon_url: h.icon_url,
            downloads: h.downloads,
            follows: h.follows,
            categories: h.categories,
            client_side: h.client_side,
            server_side: h.server_side,
            date_modified: h.date_modified,
        })
        .collect();

    Ok(ModrinthSearchResponse { hits, total_hits: raw.total_hits, offset: raw.offset, limit: raw.limit })
}


/// Newest version of a project that has files for the pack's Minecraft version and loader.
async fn modrinth_pick_version(client: &reqwest::Client, game_version: &str, loader: &str, project_id: &str) -> Result<ModrinthVersion, String> {
    let loaders_text = serde_json::json!([loader]).to_string();
    let game_versions_text = serde_json::json!([game_version]).to_string();
    let versions: Vec<ModrinthVersion> = client
        .get(format!("{MODRINTH_API}/project/{project_id}/version"))
        .header("User-Agent", MODRINTH_UA)
        .query(&[("loaders", loaders_text.as_str()), ("game_versions", game_versions_text.as_str())])
        .send().await
        .map_err(|e| format!("Не удалось получить версии мода: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Версии мода недоступны: {e}"))?
        .json().await
        .map_err(|e| format!("Не удалось разобрать версии мода: {e}"))?;
    versions.into_iter()
        .find(|v| v.files.iter().any(|f| f.filename.to_lowercase().ends_with(".jar")))
        .ok_or_else(|| format!("Для Minecraft {game_version} и загрузчика {loader} у этого мода нет файлов"))
}

/// SHA-512 of a file, used to verify Modrinth downloads.
fn compute_file_sha512(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("Не удалось открыть {}: {e}", path.display()))?;
    let mut hasher = sha2::Sha512::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|e| format!("Не удалось прочитать {}: {e}", path.display()))?;
        if read == 0 { break; }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Install a Modrinth mod into the game `mods/` directory.
/// - blocked projects are refused
/// - files that belong to the base modpack are never overwritten
/// - the download is verified with the SHA-512 published by Modrinth
/// - the file is registered as an approved user mod and remembered in the Modrinth state
/// Returns the installed file name.
#[tauri::command]
async fn modrinth_install_mod(
    app: AppHandle,
    game_dir: String,
    project_id: String,
    game_version: Option<String>,
    loader: Option<String>,
    overwrite: Option<bool>,
) -> Result<String, String> {
    let overwrite = overwrite.unwrap_or(false);
    let (mc_version, config_loader) = pack_game_version(game_version)?;
    let project_loader = loader.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).unwrap_or(config_loader);
    let game_path = expand_windows_path(&game_dir);

    let mut state = load_modrinth_state();
    if refresh_moderation().await.blocked.iter().any(|b| b == &project_id) {
        return Err("Этот мод заблокирован модератором и не может быть установлен".into());
    }

    let client = modrinth_client()?;
    // Whatever the search showed, only client mods may be installed (checked against Modrinth itself).
    let project: serde_json::Value = client
        .get(format!("{MODRINTH_API}/project/{project_id}"))
        .header("User-Agent", MODRINTH_UA)
        .send().await
        .map_err(|e| format!("Не удалось получить сведения о моде: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Сведения о моде недоступны: {e}"))?
        .json().await
        .map_err(|e| format!("Не удалось разобрать сведения о моде: {e}"))?;
    let client_side = project.get("client_side").and_then(|v| v.as_str()).unwrap_or("");
    let server_side = project.get("server_side").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(client_side, "required" | "optional") || !matches!(server_side, "optional" | "unsupported") {
        return Err("Можно скачивать только клиентские моды: этот мод нужен ещё и на сервере или не работает на клиенте".into());
    }
    let version = modrinth_pick_version(&client, &mc_version, &project_loader, &project_id).await?;
    let file = version.files.iter()
        .find(|f| f.primary && f.filename.to_lowercase().ends_with(".jar"))
        .or_else(|| version.files.iter().find(|f| f.filename.to_lowercase().ends_with(".jar")))
        .ok_or_else(|| "У версии мода нет подходящего .jar файла".to_string())?;

    if !file.url.to_lowercase().starts_with("https://") {
        return Err("Modrinth вернул небезопасную ссылку на файл".into());
    }
    let single_segment = Path::new(&file.filename).components().count() == 1;
    if !single_segment || file.filename.contains("..") {
        return Err("Недопустимое имя файла мода".into());
    }

    let mods_dir = game_path.join("mods");
    fs::create_dir_all(&mods_dir).map_err(|e| format!("Не удалось создать папку mods: {e}"))?;
    let target = mods_dir.join(&file.filename);

    if modpack_file_set(&game_path).contains(&format!("mods/{}", file.filename)) {
        return Err(format!("Файл {} входит в сборку — лаунчер не перезаписывает моды сборки", file.filename));
    }

    let expected_sha512 = file.hashes.as_ref().and_then(|h| h.sha512.clone()).filter(|h| !h.is_empty());
    if target.exists() && !overwrite {
        let matches = match (&expected_sha512, compute_file_sha512(&target)) {
            (Some(expected), Ok(actual)) => actual.eq_ignore_ascii_case(expected),
            _ => false,
        };
        if matches {
            state.installed.insert(project_id, InstalledProject { filename: file.filename.clone(), version_number: version.version_number.clone() });
            save_modrinth_state(&state)?;
            return Ok(file.filename.clone());
        }
        return Err(format!("Файл {} уже существует и отличается. Подтвердите перезапись.", file.filename));
    }

    let mod_label = file.filename.trim_end_matches(".jar").to_string();
    let total_size = Some(file.size).filter(|s| *s > 0);
    emit_progress(&app, &format!("Скачивание мода {mod_label}..."), 0, total_size);
    let response = client.get(&file.url).header("User-Agent", MODRINTH_UA).send().await
        .map_err(|e| format!("Не удалось скачать мод: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Не удалось скачать мод: {e}"))?;
    let total = response.content_length().or(total_size);
    let mut downloaded = 0u64;
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Ошибка загрузки мода: {e}"))?;
        downloaded += chunk.len() as u64;
        bytes.extend_from_slice(&chunk);
        emit_progress(&app, &format!("Скачивание мода {mod_label}..."), downloaded, total);
    }
    if bytes.is_empty() { return Err("Скачанный файл мода пуст".into()); }

    let actual_sha512 = format!("{:x}", sha2::Sha512::digest(&bytes));
    if let Some(expected) = expected_sha512.as_deref() {
        if !actual_sha512.eq_ignore_ascii_case(expected) {
            return Err(format!("Проверка SHA-512 не пройдена: ожидался {expected}, получен {actual_sha512}"));
        }
    }

    emit_progress(&app, &format!("Установка мода {mod_label}..."), downloaded, total);
    let tmp = target.with_extension("jar.part");
    fs::write(&tmp, &bytes).map_err(|e| format!("Не удалось записать {}: {e}", file.filename))?;
    if target.exists() { fs::remove_file(&target).map_err(|e| format!("Не удалось заменить {}: {e}", file.filename))?; }
    fs::rename(&tmp, &target).map_err(|e| format!("Не удалось установить {}: {e}", file.filename))?;

    let mut manifest = load_user_mods_manifest(&game_path)?;
    let mod_id = file.filename.strip_suffix(".jar").unwrap_or(&file.filename).to_string();
    let display_name = if version.name.trim().is_empty() { file.filename.clone() } else { version.name.clone() };
    manifest.mods.insert(mod_id.clone(), UserMod {
        id: mod_id,
        filename: file.filename.clone(),
        hash: actual_sha512,
        enabled: true,
        approved: true,
        display_name: Some(display_name),
        version: Some(version.version_number.clone()),
    });
    save_user_mods_manifest(&game_path, &manifest)?;

    state = load_modrinth_state();
    state.installed.insert(project_id, InstalledProject { filename: file.filename.clone(), version_number: version.version_number });
    save_modrinth_state(&state)?;

    emit_progress(&app, "Готово", 1, Some(1));
    Ok(file.filename.clone())
}

/// Installed and blocked Modrinth project ids.
#[tauri::command]
async fn get_extra_mods_state() -> Result<ExtraModsState, String> {
    let state = load_modrinth_state();
    let moderation = refresh_moderation().await;
    let mut installed: Vec<String> = state.installed.keys().cloned().collect();
    installed.sort();
    let mut blocked = moderation.blocked.clone();
    blocked.sort();
    Ok(ExtraModsState { installed, blocked, titles: moderation.titles.clone() })
}

/// Open a link in the system browser. Only http/https are allowed.
#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    let target = url.trim();
    let lower = target.to_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err("Разрешены только http/https ссылки".into());
    }
    #[cfg(windows)]
    {
        Command::new("cmd").args(["/C", "start", "", target]).spawn().map_err(|e| format!("Не удалось открыть ссылку: {e}"))?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        Command::new("xdg-open").arg(target).spawn().map_err(|e| format!("Не удалось открыть ссылку: {e}"))?;
        Ok(())
    }
}


// ===================== Server auth client (Bukkit plugin API) =====================

/// HMAC-SHA256 in hex, implemented on top of sha2 so the launcher needs no extra crate.
fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let block = 64usize;
    let mut key_block = [0u8; 64];
    if key.len() > block {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for i in 0..block {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("{:x}", outer.finalize())
}

/// Shared key for signing server requests.
///
/// The key is baked into the launcher at build time from the CI secret
/// (GORIZONT_HMAC_SECRET via `option_env!`), so players never configure anything.
/// A runtime environment variable is honoured only for local development.
/// Honest limitation: the key ships inside the exe and can be extracted, so this
/// protects against random/accidental requests, not against a targeted attacker.
fn server_hmac_secret() -> Option<String> {
    let embedded = option_env!("GORIZONT_HMAC_SECRET").unwrap_or("").trim();
    if !embedded.is_empty() { return Some(embedded.to_string()); }
    env::var("GORIZONT_HMAC_SECRET").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn server_api_base() -> Result<String, String> {
    let config = launcher_config()?;
    let base = config.server_api_url.trim().trim_end_matches('/').to_string();
    if base.is_empty() { return Err("В launcher.config.json не задан server_api_url".into()); }
    Ok(base)
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ServerAuthReply {
    /// registered | already_exists | ok | invalid_password | not_found | invalid_input | locked | error
    status: String,
    #[serde(default)]
    error: Option<String>,
}

/// Build a fresh signature header: t=<unix>,n=<nonce>,v1=<hmac over "t\nnonce\nbody">.
fn signed_headers(secret: &str, body: &str) -> (String, String) {
    let timestamp = chrono::Utc::now().timestamp();
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let canonical = format!("{timestamp}\n{nonce}\n{body}");
    let signature = hmac_sha256_hex(secret.as_bytes(), canonical.as_bytes());
    (format!("t={timestamp},n={nonce},v1={signature}"), nonce)
}

/// Signed request to the plugin API; returns the raw response text.
async fn server_api_raw(path: &str, body: Option<String>) -> Result<String, String> {
    let secret = server_hmac_secret().ok_or_else(|| {
        "Не задан GORIZONT_HMAC_SECRET — вход через сервер недоступен. Задайте тот же ключ, что в auth.hmacSecret плагина.".to_string()
    })?;
    let base = server_api_base()?;
    let body_text = body.unwrap_or_default();
    let (signature, _nonce) = signed_headers(&secret, &body_text);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let response = if body_text.is_empty() {
        client.get(format!("{base}{path}")).header("X-Gorizont-Signature", &signature)
    } else {
        client.post(format!("{base}{path}")).header("X-Gorizont-Signature", &signature)
            .header("Content-Type", "application/json").body(body_text.clone())
    };
    let response = response.send().await.map_err(|e| format!("Сервер авторизации недоступен: {e}"))?;
    let status_code = response.status();
    let text = response.text().await.map_err(|e| format!("Не удалось прочитать ответ сервера: {e}"))?;
    if status_code == 401 {
        return Err("Сервер отклонил подпись запроса: проверьте, что GORIZONT_HMAC_SECRET совпадает с auth.hmacSecret".into());
    }
    if !status_code.is_success() {
        return Err(format!("Сервер авторизации вернул HTTP {status_code}: {text}"));
    }
    Ok(text)
}

async fn server_api_call(path: &str, body: Option<String>) -> Result<ServerAuthReply, String> {
    let text = server_api_raw(path, body).await?;
    serde_json::from_str::<ServerAuthReply>(&text).map_err(|e| format!("Некорректный ответ сервера: {e}"))
}

fn credentials_body(nickname: &str, password: &str) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "nickname": nickname,
        "password": password,
        "device_fp": "gorizont-launcher",
    })).map_err(|e| e.to_string())
}

/// Register on the game server (source of truth for accounts).
#[tauri::command]
async fn server_auth_register(nickname: String, password: String) -> Result<ServerAuthReply, String> {
    let body = credentials_body(&nickname, &password)?;
    server_api_call("/auth/register", Some(body)).await
}

/// Log in on the game server (source of truth for accounts).
#[tauri::command]
async fn server_auth_login(nickname: String, password: String) -> Result<ServerAuthReply, String> {
    let body = credentials_body(&nickname, &password)?;
    server_api_call("/auth/login", Some(body)).await
}

/// Sign the check-player request; used to confirm the launcher session server-side.
#[tauri::command]
async fn server_auth_check_player(nickname: String) -> Result<serde_json::Value, String> {
    let secret = server_hmac_secret().ok_or_else(|| "Не задан GORIZONT_HMAC_SECRET".to_string())?;
    let base = server_api_base()?;
    let path = format!("/auth/check-player?nickname={}", urlencoding_encode(&nickname));
    let (signature, _nonce) = signed_headers(&secret, "");
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let response = client.get(format!("{base}{path}")).header("X-Gorizont-Signature", &signature).send().await
        .map_err(|e| format!("Сервер авторизации недоступен: {e}"))?;
    let text = response.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("Некорректный ответ сервера: {e}"))
}

/// Server-wide mod moderation: Modrinth projects hidden from everyone and mod files approved to stay.
#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ModerationState {
    /// Modrinth project ids blocked by a moderator.
    #[serde(default)]
    blocked: Vec<String>,
    /// SHA-256 of mod files approved by a moderator.
    #[serde(default)]
    approved: Vec<String>,
    /// Human readable names for the keys above.
    #[serde(default)]
    titles: HashMap<String, String>,
}

fn moderation_cache_path() -> Result<PathBuf, String> {
    Ok(launcher_data_dir()?.join("moderation.json"))
}

fn load_moderation_cache() -> Option<ModerationState> {
    let text = fs::read_to_string(moderation_cache_path().ok()?).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_moderation_cache(state: &ModerationState) {
    if let Ok(path) = moderation_cache_path() {
        if let Ok(text) = serde_json::to_string_pretty(state) { let _ = fs::write(path, text); }
    }
}

/// Fresh lists from the server; the last cached copy when the server cannot be reached.
async fn refresh_moderation() -> ModerationState {
    let fetched = server_api_raw("/mods/moderation", None).await
        .and_then(|text| serde_json::from_str::<ModerationState>(&text).map_err(|e| format!("Некорректный ответ сервера: {e}")));
    match fetched {
        Ok(state) => { save_moderation_cache(&state); state }
        Err(e) => {
            eprintln!("[MOD] moderation lists unavailable, using the cached copy: {e}");
            load_moderation_cache().unwrap_or_default()
        }
    }
}

/// Catalog mods that a moderator has since blocked are moved out of `mods` (into `mods-blocked`).
fn enforce_blocked_mods(game_path: &Path) {
    let Some(moderation) = load_moderation_cache() else { return };
    let mut state = load_modrinth_state();
    let mods_dir = game_path.join("mods");
    let blocked_dir = game_path.join("mods-blocked");
    let mut changed = false;
    for id in &moderation.blocked {
        if let Some(installed) = state.installed.remove(id) {
            let path = mods_dir.join(&installed.filename);
            if path.is_file() {
                let _ = fs::create_dir_all(&blocked_dir);
                let _ = fs::rename(&path, blocked_dir.join(&installed.filename));
            }
            changed = true;
        }
    }
    if changed { let _ = save_modrinth_state(&state); }
}

/// Current server-wide moderation lists (works from the cache when the server is offline).
#[tauri::command]
async fn get_moderation() -> Result<ModerationState, String> {
    Ok(refresh_moderation().await)
}

/// Moderator action: block/unblock a Modrinth project, approve/unapprove a mod file by its SHA-256.
/// The server accepts it only from a configured moderator account and checks that account's password.
#[tauri::command]
async fn moderate_mod(nickname: String, password: String, action: String, key: String, title: Option<String>) -> Result<ModerationState, String> {
    let body = serde_json::to_string(&serde_json::json!({
        "nickname": nickname,
        "password": password,
        "action": action,
        "key": key,
        "title": title.unwrap_or_default(),
    })).map_err(|e| e.to_string())?;
    let reply = server_api_call("/mods/moderate", Some(body)).await?;
    match reply.status.as_str() {
        "ok" => Ok(refresh_moderation().await),
        "forbidden" => Err("Управлять модами может только модератор".into()),
        "invalid_password" => Err("Неверный пароль модератора".into()),
        other => Err(reply.error.clone().unwrap_or_else(|| format!("Сервер модерации: {other}"))),
    }
}

/// Minimal percent-encoding for query values (RFC 3986 unreserved characters stay as-is).
fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Local mirror of a server account: create it when missing, then issue launcher tokens.
async fn local_login_or_mirror(pool: &DbPool, nickname: &str, password: &str, device_fp: &str) -> Result<AuthResponse, String> {
    match auth::login_user(pool, nickname, password, true, device_fp).await {
        Ok(response) => Ok(response),
        Err(_) => {
            // The account lives on the game server; keep a local mirror for offline tokens.
            let _ = auth::register_user(pool, nickname, password, device_fp).await;
            auth::login_user(pool, nickname, password, true, device_fp).await
        }
    }
}


fn main() { 
    eprintln!("[MAIN] Starting Gorizont Launcher");
    std::io::stderr().flush().ok();
    
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_sql::Builder::new().build())
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::block_on(async move {
                let db_pool = init_db(&app_handle).await.expect("Failed to initialize database");
                app.manage(db_pool.clone());
                // Account signed in inside the launcher, shared with the local HTTP API.
                let active_accounts: ActiveAccountState = std::sync::Arc::new(std::sync::RwLock::new(None));
                app.manage(active_accounts.clone());
                let api_port = launcher_config().map(|c| c.launcher_api_port).unwrap_or_else(|_| default_launcher_api_port());
                
                // Start HTTP server on port 8080 for server mod communication
                let http_pool = db_pool.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = start_http_server(http_pool, active_accounts, api_port).await {
                        eprintln!("[HTTP] Server error: {}", e);
                    }
                });
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_system_memory,
            prepare_game_files,
            lookup_mojang_profile,
            download_and_extract_modpack,
            check_and_update_modpack,
            check_launcher_update,
            get_releases_json,
            download_launcher_update,
            launch_minecraft,
            link_ip_to_account,
            auth_login,
            auth_register,
            auth_refresh,
            auth_logout,
            auth_me,
            auth_forgot_password,
            auth_oauth,
            // User mods commands
            scan_user_mods_cmd,
            get_user_mods,
            toggle_user_mod,
            approve_user_mod,
            remove_user_mod_tracking,
            backup_user_mods,
            restore_user_mods,
            // Additional (optional) mods catalog
            get_extra_mods_catalog,
            download_extra_mod,
            // Modrinth discover + blocked mods
            modrinth_search,
            modrinth_install_mod,
            get_extra_mods_state,
            get_moderation,
            moderate_mod,
            open_external_url,
            server_auth_register,
            server_auth_login,
            server_auth_check_player,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Gorizont Launcher"); 
}

#[cfg(test)]
mod server_auth_tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case2() {
        // RFC 4231, test case 2: key "Jefe", data "what do ya want for nothing?"
        let digest = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(digest, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn signature_header_has_timestamp_nonce_and_hex() {
        let (header, nonce) = signed_headers("secret", "{\"nickname\":\"A\"}");
        assert!(header.starts_with("t="));
        assert!(header.contains(&format!(",n={nonce},")));
        let signature = header.split(",v1=").nth(1).expect("v1 part");
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signature_changes_for_different_bodies() {
        let (first, _) = signed_headers("secret", "body-a");
        let (second, _) = signed_headers("secret", "body-b");
        assert_ne!(first.split(",v1=").nth(1), second.split(",v1=").nth(1));
    }
    /// Network test: the pack file list must be readable from the real release without downloading the pack.
    #[test]
    #[ignore]
    fn reads_pack_file_list_from_github() {
        let url = "https://github.com/YaroslavPetrushenko/GorizontLauncher/releases/download/pack-2.6.0/modpack.zip";
        let names = tauri::async_runtime::block_on(remote_zip_names(url)).expect("read central directory");
        let jars = names.iter().filter(|n| n.starts_with("mods/") && n.ends_with(".jar")).count();
        assert_eq!(jars, 57, "mod jars in pack-2.6.0, names: {:?}", &names[..names.len().min(5)]);
        assert!(names.iter().any(|n| n == "manifest.json"));
    }

    #[test]
    fn client_only_facets_exclude_server_mods() {
        let facets = modrinth_facets("1.21.1", "neoforge", &[]).to_string();
        assert!(facets.contains("client_side:required") && facets.contains("client_side:optional"));
        assert!(!facets.contains("client_side:unknown"));
        assert!(facets.contains("server_side:unsupported") && facets.contains("server_side:optional"));
        assert!(!facets.contains("server_side:required"));
    }
}
