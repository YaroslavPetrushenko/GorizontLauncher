#![cfg_attr(not(debug_assertions), windows_subsystem = "console")]

mod servers;

use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, io::{self, Read, Write}, path::{Path, PathBuf}, process::Command};
use tauri::{AppHandle, Emitter, Manager};
use zip::ZipArchive;

const VERSION_ID: &str = "1.21.1-neoforge";
const WEBHOOK_URL: &str = "";
const WEBHOOK_TOKEN: &str = "";
const JAVA_DOWNLOAD_URL: &str = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse";

fn expand_windows_path(input: &str) -> PathBuf {
    let mut value = input.to_string();
    if value.contains("%APPDATA%") { if let Ok(app_data) = env::var("APPDATA") { value = value.replace("%APPDATA%", &app_data); } }
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
    loader_type: String,
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
        value.get("values").and_then(|items| items.as_array()).map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()).unwrap_or_default()
    }).map(|value| replacements.iter().fold(value, |text, (key, replacement)| text.replace(key, replacement))).collect()
}

#[derive(Deserialize)]
struct LibraryEntry { artifact: Option<LibraryArtifact>, name: Option<String>, rules: Option<Vec<serde_json::Value>> }

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

fn resolve_version_id(config: &LauncherConfig, override_opt: &Option<VersionOverride>) -> String {
    let mc = override_opt.as_ref().and_then(|o| o.minecraft_version.as_deref()).unwrap_or(&config.minecraft_version);
    let lt = override_opt.as_ref().and_then(|o| o.loader_type.as_deref()).unwrap_or(&config.loader_type);
    let lv = override_opt.as_ref().and_then(|o| o.loader_version.as_deref()).unwrap_or(&config.loader_version);
    format!("{}-{}-{}", mc, lt, lv)
}

fn version_id(config: &LauncherConfig) -> String {
    resolve_version_id(config, &None)
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
    if manifest.minecraft_version != config.minecraft_version { return Err(format!("Сборка рассчитана на Minecraft {}, а нужен {}", manifest.minecraft_version, config.minecraft_version)); }
    if manifest.loader.r#type != config.loader_type || manifest.loader.version != config.loader_version { return Err(format!("Неверный загрузчик: нужен {} {}, а в сборке {} {}", config.loader_type, config.loader_version, manifest.loader.r#type, manifest.loader.version)); }
    if manifest.pack_version.trim().is_empty() { return Err("В manifest.json отсутствует pack_version".into()); }
    Ok(())
}

fn emit_progress(app: &AppHandle, stage: &str, downloaded: u64, total: Option<u64>) {
    let percent = total.map(|t| if t > 0 { downloaded as f32 / t as f32 * 100.0 } else { 0.0 }).unwrap_or(0.0);
    let _ = app.emit("download-progress", DownloadProgress { downloaded, total, percent, stage: stage.to_string() });
}

fn safe_extract<R: io::Read + io::Seek>(archive: &mut ZipArchive<R>, target: &Path, config: &LauncherConfig) -> Result<PackManifest, String> {
    if archive.len() > 20_000 { return Err("Архив содержит слишком много файлов".into()); }
    let mut manifest: Option<PackManifest> = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| e.to_string())?;
        let enclosed = file.enclosed_name().ok_or_else(|| "Небезопасный путь в архиве".to_string())?.to_owned();
    if enclosed.components().count() == 1 && enclosed.to_string_lossy() == config.expected_manifest {
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
    let manifest = manifest.ok_or_else(|| format!("В корне modpack.zip отсутствует {}", config.expected_manifest))?;
    validate_manifest(&manifest, config)?;
    Ok(manifest)
}

#[tauri::command]
async fn download_and_extract_modpack(app: AppHandle, url: String, target_dir: String, expected_sha256: Option<String>) -> Result<(), String> {
    eprintln!("[DEBUG] download_and_extract_modpack called: url={}, target_dir={}", url, target_dir);
    let target = expand_windows_path(&target_dir); fs::create_dir_all(&target).map_err(|e| e.to_string())?; let config = launcher_config()?;
    let response = reqwest::Client::new().get(&url).header("User-Agent", "GorizontLauncher/0.1").send().await.map_err(|e| e.to_string())?;
    let total = response.content_length(); let mut downloaded = 0; let mut bytes = Vec::new(); let mut stream = response.bytes_stream();
    emit_progress(&app, "Скачивание модов...", 0, total);
    while let Some(chunk) = stream.next().await { let chunk = chunk.map_err(|e| e.to_string())?; downloaded += chunk.len() as u64; bytes.extend_from_slice(&chunk); emit_progress(&app, "Скачивание модов...", downloaded, total); }
    if let Some(expected) = expected_sha256 { let actual = format!("{:x}", Sha256::digest(&bytes)); if actual.to_lowercase() != expected.to_lowercase() { return Err("Проверка SHA-256 не пройдена".into()); } }
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
    let path = launcher_data_dir()?.join("GorizontLauncher-update.exe"); fs::write(&path, bytes).map_err(|e| e.to_string())?; emit_progress(&app, "Устанавливаем обновление поверх текущей версии...", 1, Some(1));
    // NSIS updates the existing installation in place; it is never an uninstall action.
    Command::new(&path).arg("/S").spawn().map_err(|e| format!("Не удалось запустить установщик: {e}"))?; app.exit(0); Ok(())
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
    
    let version_id = resolve_version_id(&config, &override_opt);
    let profile_dir = target.join("versions").join(&version_id);
    let jar_exists = profile_dir.join(format!("{}.jar", version_id)).exists();
    let json_exists = profile_dir.join(format!("{}.json", version_id)).exists();
    let libs_dir = target.join("libraries");
    let libs_exist = libs_dir.exists() && libs_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    let mods_dir = target.join("mods");
    let mods_exist = mods_dir.exists() && mods_dir.read_dir().map(|d| d.count()).unwrap_or(0) > 0;
    
    // FIRST: Check if already installed with valid marker and correct version folder
    if let Ok(text) = fs::read_to_string(&marker) {
        log(&format!("marker read, installed version={:?}", text));
        if let Ok(installed) = serde_json::from_str::<PackManifest>(&text) {
            log(&format!("manifest parsed: pack_version={}", installed.pack_version));
            if validate_manifest(&installed, &effective_config).is_ok() {
                log("manifest validation passed");
                if jar_exists && json_exists && libs_exist {
                    log("jar, json and libraries exist, returning installed version");
                    return Ok(installed.pack_version);
                } else {
                    log(&format!("jar_exists={}, json_exists={}, libs_exist={}, mods_exist={}, profile_dir={:?}", jar_exists, json_exists, libs_exist, mods_exist, profile_dir));
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
                let manifest_text = manifest_text.replace("\"\"", "\"");
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
                    log(&format!("GitHub fallback: latest={}, local_version={}", latest, local_version));
                    if let Some(asset_url) = asset_url {
                        if latest != local_version.trim_start_matches('v') || !marker.exists() || !jar_exists || !json_exists {
                            log("Downloading from GitHub...");
                            download_and_extract_modpack(app, asset_url, target_dir, None).await?;
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

/// Keep at least 2 GB for Windows and other apps; never allocate more than the PC really has.
fn clamp_ram_mb(requested: u32) -> u32 {
    let max = read_system_memory().map(|m| (m.total_mb.saturating_sub(2048)).max(2048) as u32).unwrap_or(8192);
    requested.clamp(1024, max)
}

#[tauri::command]
fn get_system_memory() -> Result<SystemMemory, String> { read_system_memory().ok_or_else(|| "Не удалось определить объём ОЗУ".to_string()) }

#[tauri::command]
async fn launch_minecraft(app: AppHandle, username: String, ram_mb: u32, game_dir: String, java_path: Option<String>, launcher_jar: Option<String>, version_override: Option<String>) -> Result<(), String> {
    eprintln!("[LAUNCH] launch_minecraft called: username={}, ram_mb={}, game_dir={}", username, ram_mb, game_dir);
    if username.trim().is_empty() { return Err("Введите ник".into()); }
    if let Err(e) = ensure_assets(&expand_windows_path(&game_dir)) { eprintln!("[LAUNCH] ensure_assets failed: {e}"); }
    let ram = clamp_ram_mb(ram_mb); let java = match java_path.filter(|p| !p.trim().is_empty()) { Some(path) => expand_windows_path(&path), None => ensure_java(&app).await? };
    eprintln!("[LAUNCH] java path: {:?}", java);
    let config = launcher_config()?;
    let override_opt: Option<VersionOverride> = version_override.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let effective_config = resolve_effective_config(&config, &override_opt);
    let version_id = resolve_version_id(&config, &override_opt);
    let game_path = expand_windows_path(&game_dir);
    eprintln!("[LAUNCH] game_path={:?}, version_id={}", game_path, version_id);
    let jar = launcher_jar.map(|p| expand_windows_path(&p)).unwrap_or_else(|| game_path.join("versions").join(&version_id).join(format!("{version_id}.jar")));
    eprintln!("[LAUNCH] jar path: {:?}, exists={}", jar, jar.exists());
    if !jar.exists() { return Err(format!("Файл Minecraft не найден: {}. Сначала добавьте modpack.zip с клиентом или укажите правильную папку игры.", jar.display())); }
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
    }).filter_map(|library| library.artifact.map(|a| {
        // Some profiles (TLauncher) store paths with a "libraries/" prefix, others without it.
        let direct = game_path.join(&a.path);
        if direct.exists() { direct } else { game_path.join("libraries").join(&a.path) }
    })).filter(|path| path.exists()).map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>();
    let assets_index = profile.assets.clone().unwrap_or_else(|| config.minecraft_version.clone());
    let classpath = libraries.into_iter().chain(std::iter::once(jar.to_string_lossy().to_string())).collect::<Vec<_>>().join(";");
    let replacements = [("${auth_player_name}", username.clone()), ("${version_name}", version_id.clone()), ("${game_directory}", game_path.to_string_lossy().to_string()), ("${assets_root}", game_path.join("assets").to_string_lossy().to_string()), ("${assets_index_name}", assets_index.clone()), ("${auth_access_token}", "0".into()), ("${auth_uuid}", "00000000000000000000000000000000".into()), ("${auth_xuid}", "".into()), ("${clientid}", "".into()), ("${launcher_name}", "GorizontLauncher".into()), ("${launcher_version}", env!("CARGO_PKG_VERSION").into()), ("${classpath}", classpath.clone()), ("${natives_directory}", game_path.join("versions").join(&version_id).join("natives").to_string_lossy().to_string()), ("${library_directory}", game_path.join("libraries").to_string_lossy().to_string()), ("${classpath_separator}", ";".into()), ("${user_type}", "mojang".into()), ("${version_type}", "release".into()), ("${resolution_width}", "854".into()), ("${resolution_height}", "480".into()), ("${quickPlayPath}", "".into()), ("${quickPlaySingleplayer}", "false".into()), ("${quickPlayMultiplayer}", "false".into()), ("${quickPlayRealms}", "false".into())];
    let LaunchArguments { jvm, game } = profile.arguments.unwrap_or(LaunchArguments { jvm: None, game: None });
    let mut args = vec![format!("-Xmx{ram}M"), format!("-Xms{}M", ram.min(2048))];
    if let Some(jvm) = jvm { args.extend(profile_values(&jvm, &replacements)); }
    args.extend(["-cp".into(), classpath, profile.main_class.unwrap_or_else(|| "cpw.mods.bootstraplauncher.BootstrapLauncher".into())]);
    if let Some(game) = game { args.extend(profile_values(&game, &replacements)); }
    args.extend(["--server".into(), effective_config.server_address.clone(), "--port".into(), effective_config.server_port.to_string()]);
    eprintln!("[LAUNCH] spawning java with args: {:?}", args);
    // Make sure the Gorizont server is in the multiplayer list.
    match servers::ensure_default_server(&game_path, "Gorizont", &server) { Ok(changed) => eprintln!("[LAUNCH] servers.dat updated={changed}"), Err(e) => eprintln!("[LAUNCH] servers.dat error: {e}") }
    let java_log_path = game_path.join("launcher-java.log");
    let java_log = fs::File::create(&java_log_path).map_err(|e| format!("Не удалось создать лог Java: {e}"))?;
    let java_err = java_log.try_clone().map_err(|e| e.to_string())?;
    let mut child = Command::new(java).args(args).current_dir(&game_path).env("GORIZONT_SERVER", server).stdout(std::process::Stdio::from(java_log)).stderr(std::process::Stdio::from(java_err)).spawn().map_err(|e| format!("Не удалось запустить Java: {e}"))?; 
    eprintln!("[LAUNCH] Java spawned successfully");
    // Hide the launcher while Minecraft is running and bring it back when the game exits.
    let window = app.get_webview_window("main");
    if let Some(w) = &window { let _ = w.hide(); }
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("[LAUNCH] Minecraft exited: {:?}", status);
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
    if WEBHOOK_URL.is_empty() || WEBHOOK_TOKEN.is_empty() { return Err("Веб-хук не настроен в конфигурации лаунчера".into()); }
    Client::new().post(WEBHOOK_URL).bearer_auth(WEBHOOK_TOKEN).json(&serde_json::json!({"username": username})).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?; Ok(())
}

fn main() { 
    eprintln!("[MAIN] Starting Gorizont Launcher");
    std::io::stderr().flush().ok();
    // Test file write
    let _ = std::fs::write("C:\\test_launcher.txt", "MAIN CALLED");
    tauri::Builder::default().plugin(tauri_plugin_shell::init()).invoke_handler(tauri::generate_handler![get_system_memory, lookup_mojang_profile, download_and_extract_modpack, check_and_update_modpack, check_launcher_update, download_launcher_update, launch_minecraft, link_ip_to_account]).run(tauri::generate_context!()).expect("error while running Gorizont Launcher"); 
}
