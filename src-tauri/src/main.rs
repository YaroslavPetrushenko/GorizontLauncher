#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod servers;

use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, io::{self, Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}};
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
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
}

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

fn version_newer(candidate: &str, current: &str) -> bool {
    let parse = |version: &str| version.split('.').map(|part| part.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    let candidate = parse(candidate); let current = parse(current);
    for index in 0..candidate.len().max(current.len()) { let left = *candidate.get(index).unwrap_or(&0); let right = *current.get(index).unwrap_or(&0); if left != right { return left > right; } }
    false
}

#[derive(Clone, Serialize)] struct DownloadProgress { downloaded: u64, total: Option<u64>, percent: f32, stage: String }
#[derive(Deserialize)] struct Release { tag_name: String, assets: Vec<Asset> }
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
    let mods_dir = target.join("mods");
    let old_dir = target.join("mods-old");
    if let Ok(entries) = fs::read_dir(&mods_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_file() && name.to_lowercase().ends_with(".jar") && !keep.contains(&name) {
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
    fs::write(target.join(".gorizont-installed.json"), serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    emit_progress(&app, "Готово", 1, Some(1)); Ok(())
}

#[tauri::command]
async fn check_launcher_update() -> Result<Option<LauncherUpdate>, String> {
    let config = launcher_config()?;
    let releases: Vec<serde_json::Value> = reqwest::Client::new().get(releases_api_url(&config)).header("User-Agent", "GorizontLauncher/1.0").send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
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
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().map_err(|e| format!("client: {e}"))?;
    let response = client.get(releases_api_url(config)).header("User-Agent", "GorizontLauncher/1.0").send().await.map_err(|e| format!("запрос: {e}"))?;
    let status = response.status();
    if !status.is_success() { return Err(format!("GitHub ответил {status}")); }
    let releases = response.json::<Vec<Release>>().await.map_err(|e| format!("разбор ответа: {e}"))?;
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
                                log("jar, json, libraries and mods exist and pack is up to date");
                                return Ok(installed.pack_version);
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
                log("Installing from local modpack...");
                let bytes = fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?;
                log(&format!("Read modpack zip: {} bytes", bytes.len()));
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
                
                // Extract all files from zip
                log("Extracting all files from zip...");
                // Reset cursor to beginning for re-reading
                let cursor2 = io::Cursor::new(fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?);
                let mut archive2 = ZipArchive::new(cursor2).map_err(|e| format!("Некорректный ZIP архив: {}", e))?;
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
                }
                log("All files extracted");
                
                // Remove stale mods that are no longer in the pack
                let cursor3 = io::Cursor::new(fs::read(&local_path).map_err(|e| format!("Не удалось прочитать локальный модпак: {e}"))?);
                let mut archive3 = ZipArchive::new(cursor3).map_err(|e| format!("Некорректный ZIP архив: {}", e))?;
                retire_stale_mods(&mut archive3, &target);
                log("Stale mods retired");
                
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
                log(&format!("Local modpack installed, version={}", installed_version));
                return Ok(installed_version);
            } else {
                log("Local modpack already installed, returning version from marker");
                if let Ok(text) = fs::read_to_string(&marker) {
                    if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
                        return Ok(installed.pack_version);
                    }
                }
                return Ok("local".to_string());
            }
        }
    }
    
    // THIRD: Fallback to GitHub releases (only if no local modpack configured)
    let client = reqwest::Client::new();
    if let Ok(response) = client.get(releases_api_url(&effective_config)).header("User-Agent", "GorizontLauncher/0.1").send().await {
        if let Ok(response) = response.error_for_status() {
            if let Ok(releases) = response.json::<Vec<Release>>().await {
                if let Some(release) = releases.into_iter().find(|r| r.assets.iter().any(|a| a.name == effective_config.modpack_asset)) {
                    let latest = release.tag_name.trim_start_matches('v').trim_start_matches("pack-").to_string();
                    let asset_url = release.assets.iter().find(|a| a.name == effective_config.modpack_asset).map(|a| a.browser_download_url.clone());
                    let signature_url = release.assets.iter().find(|a| a.name == "modpack.sig").map(|a| a.browser_download_url.clone());
                    log(&format!("GitHub fallback: latest={}, local_version={}", latest, local_version));
                    if let Some(asset_url) = asset_url {
                        if force_update || latest != local_version.trim_start_matches('v') || !marker.exists() {
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
    let loader = read_installed_loader(&game_path, &effective_config);
    let version_id = loader_version_id(&loader);
    if let Err(e) = ensure_assets(&game_path) { eprintln!("[PREPARE] ensure_assets failed: {e}"); }
    if !version_id.is_empty() { ensure_loader(&app, &game_path, &loader).await?; }
    ensure_game_files(&app, &game_path, &version_id).await
}

#[tauri::command]
async fn launch_minecraft(app: AppHandle, username: String, ram_mb: u32, game_dir: String, java_path: Option<String>, launcher_jar: Option<String>, version_override: Option<String>) -> Result<(), String> {
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
    let replacements = [("${auth_player_name}", username.clone()), ("${version_name}", version_id.clone()), ("${game_directory}", game_path.to_string_lossy().to_string()), ("${assets_root}", game_path.join("assets").to_string_lossy().to_string()), ("${assets_index_name}", assets_index.clone()), ("${auth_access_token}", "0".into()), ("${auth_uuid}", "00000000000000000000000000000000".into()), ("${auth_xuid}", "".into()), ("${clientid}", "".into()), ("${launcher_name}", "GorizontLauncher".into()), ("${launcher_version}", env!("CARGO_PKG_VERSION").into()), ("${classpath}", classpath.clone()), ("${natives_directory}", escape_windows_arg(&game_path.join("versions").join(&version_id).join("natives").to_string_lossy().to_string())), ("${library_directory}", escape_windows_arg(&game_path.join("libraries").to_string_lossy().to_string())), ("${classpath_separator}", ";".into()), ("${user_type}", "mojang".into()), ("${version_type}", "release".into()), ("${resolution_width}", "854".into()), ("${resolution_height}", "480".into()), ("${quickPlayPath}", "".into()), ("${quickPlaySingleplayer}", "false".into()), ("${quickPlayMultiplayer}", "false".into()), ("${quickPlayRealms}", "false".into())];
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

fn main() { 
    eprintln!("[MAIN] Starting Gorizont Launcher");
    std::io::stderr().flush().ok();
    tauri::Builder::default().plugin(tauri_plugin_shell::init()).invoke_handler(tauri::generate_handler![get_system_memory, prepare_game_files, lookup_mojang_profile, download_and_extract_modpack, check_and_update_modpack, check_launcher_update, download_launcher_update, launch_minecraft, link_ip_to_account]).run(tauri::generate_context!()).expect("error while running Gorizont Launcher"); 
}
