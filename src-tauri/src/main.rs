#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Read}, path::{Path, PathBuf}, process::Command};
use tauri::{AppHandle, Emitter};
use zip::ZipArchive;

const VERSION_ID: &str = "1.21.1-neoforge";
const WEBHOOK_URL: &str = "";
const WEBHOOK_TOKEN: &str = "";

#[derive(Deserialize)]
struct LauncherConfig {
    github_owner: String,
    github_repo: String,
    modpack_asset: String,
    expected_manifest: String,
    pack_id: String,
    minecraft_version: String,
    launch_version_id: String,
    loader_type: String,
    loader_version: String,
}

#[derive(Deserialize)]
struct PackManifest {
    schema_version: u32,
    pack_id: String,
    pack_version: String,
    minecraft_version: String,
    loader: LoaderManifest,
}

#[derive(Deserialize)]
struct LoaderManifest {
    r#type: String,
    version: String,
}

fn launcher_config() -> Result<LauncherConfig, String> {
    serde_json::from_str(include_str!("../../launcher.config.json")).map_err(|e| format!("Ошибка launcher.config.json: {e}"))
}

fn releases_api_url(config: &LauncherConfig) -> String {
    format!("https://api.github.com/repos/{}/{}/releases?per_page=30", config.github_owner, config.github_repo)
}

#[derive(Clone, Serialize)] struct DownloadProgress { downloaded: u64, total: Option<u64>, percent: f32, stage: String }
#[derive(Deserialize)] struct Release { tag_name: String, assets: Vec<Asset> }
#[derive(Deserialize)] struct Asset { name: String, browser_download_url: String }

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
    let target = PathBuf::from(&target_dir); fs::create_dir_all(&target).map_err(|e| e.to_string())?; let config = launcher_config()?;
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
async fn check_and_update_modpack(app: AppHandle, local_version: String, target_dir: String) -> Result<String, String> {
    let config = launcher_config()?;
    let releases: Vec<Release> = reqwest::Client::new().get(releases_api_url(&config)).header("User-Agent", "GorizontLauncher/0.1").send().await.map_err(|e| format!("Не удалось получить релизы GitHub: {e}"))?.error_for_status().map_err(|e| format!("GitHub не вернул релизы: {e}"))?.json().await.map_err(|e| format!("Некорректный ответ GitHub: {e}"))?;
    // The launcher release is separate from modpack releases. Only releases carrying
    // the configured ZIP asset are considered, so launcher binaries are ignored.
    let release = releases.into_iter().find(|release| release.assets.iter().any(|asset| asset.name == config.modpack_asset));
    let release = release.ok_or_else(|| format!("В GitHub Releases нет опубликованной сборки с asset {}", config.modpack_asset))?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    if latest == local_version.trim_start_matches('v') { return Ok(latest); }
    let asset = release.assets.iter().find(|a| a.name == config.modpack_asset).ok_or_else(|| format!("В релизе нет файла {}", config.modpack_asset))?;
    download_and_extract_modpack(app, asset.browser_download_url.clone(), target_dir, None).await?;
    Ok(latest)
}

#[tauri::command]
fn launch_minecraft(username: String, ram_mb: u32, game_dir: String, java_path: Option<String>, launcher_jar: Option<String>) -> Result<(), String> {
    if username.trim().is_empty() { return Err("Введите ник".into()); }
    let ram = ram_mb.clamp(2048, 8192); let java = java_path.filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "javaw.exe".into());
    let version_id = launcher_config().map(|config| config.launch_version_id).unwrap_or_else(|_| VERSION_ID.to_string());
    let jar = launcher_jar.unwrap_or_else(|| format!("{game_dir}/versions/{version_id}/{version_id}.jar"));
    Command::new(java).args([format!("-Xmx{ram}M"), format!("-Xms{ram}M"), "-jar".into(), jar, "--username".into(), username, "--gameDir".into(), game_dir, "--version".into(), version_id]).spawn().map_err(|e| format!("Не удалось запустить Java: {e}"))?; Ok(())
}

#[tauri::command]
async fn link_ip_to_account(username: String) -> Result<(), String> {
    if WEBHOOK_URL.is_empty() || WEBHOOK_TOKEN.is_empty() { return Err("Веб-хук не настроен в конфигурации лаунчера".into()); }
    Client::new().post(WEBHOOK_URL).bearer_auth(WEBHOOK_TOKEN).json(&serde_json::json!({"username": username})).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?; Ok(())
}

fn main() { tauri::Builder::default().plugin(tauri_plugin_shell::init()).invoke_handler(tauri::generate_handler![download_and_extract_modpack, check_and_update_modpack, launch_minecraft, link_ip_to_account]).run(tauri::generate_context!()).expect("error while running Gorizont Launcher"); }
