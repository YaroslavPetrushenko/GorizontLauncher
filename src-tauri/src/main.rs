#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, io::{self, Read}, path::{Path, PathBuf}, process::Command};
use tauri::{AppHandle, Emitter};
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

fn launcher_data_dir() -> Result<PathBuf, String> {
    let base = env::var("LOCALAPPDATA").map_err(|_| "Не удалось определить LOCALAPPDATA".to_string())?;
    let path = PathBuf::from(base).join("GorizontLauncher"); fs::create_dir_all(&path).map_err(|e| e.to_string())?; Ok(path)
}

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
    server_address: String,
    server_port: u16,
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
    main_class: Option<String>,
    arguments: Option<LaunchArguments>,
    libraries: Option<Vec<LibraryEntry>>,
}

#[derive(Deserialize)]
struct LaunchArguments { jvm: Option<Vec<serde_json::Value>>, game: Option<Vec<serde_json::Value>> }

fn profile_values(values: &[serde_json::Value], replacements: &[(&str, String)]) -> Vec<String> {
    values.iter().filter_map(|value| value.as_str()).map(|value| {
        replacements.iter().fold(value.to_string(), |text, (key, replacement)| text.replace(key, replacement))
    }).collect()
}

#[derive(Deserialize)]
struct LibraryEntry { artifact: Option<LibraryArtifact> }

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
async fn launch_minecraft(app: AppHandle, username: String, ram_mb: u32, game_dir: String, java_path: Option<String>, launcher_jar: Option<String>) -> Result<(), String> {
    if username.trim().is_empty() { return Err("Введите ник".into()); }
    let ram = ram_mb.clamp(2048, 8192); let java = match java_path.filter(|p| !p.trim().is_empty()) { Some(path) => expand_windows_path(&path), None => ensure_java(&app).await? };
    let game_path = expand_windows_path(&game_dir); let version_id = launcher_config().map(|config| config.launch_version_id).unwrap_or_else(|_| VERSION_ID.to_string());
    let jar = launcher_jar.map(|p| expand_windows_path(&p)).unwrap_or_else(|| game_path.join("versions").join(&version_id).join(format!("{version_id}.jar")));
    if !jar.exists() { return Err(format!("Файл Minecraft не найден: {}. Сначала добавьте modpack.zip с клиентом или укажите правильную папку игры.", jar.display())); }
    let config = launcher_config()?; let server = format!("{}:{}", config.server_address, config.server_port);
    let profile_text = fs::read_to_string(game_path.join("versions").join(&version_id).join(format!("{version_id}.json"))).map_err(|e| format!("Не найден профиль Minecraft {version_id}: {e}"))?;
    let profile: VersionProfile = serde_json::from_str(&profile_text).map_err(|e| format!("Профиль Minecraft повреждён: {e}"))?;
    let libraries = profile.libraries.unwrap_or_default().into_iter().filter_map(|library| library.artifact.map(|a| game_path.join(a.path))).filter(|path| path.exists()).map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>();
    let classpath = libraries.into_iter().chain(std::iter::once(jar.to_string_lossy().to_string())).collect::<Vec<_>>().join(";");
    let replacements = [("${auth_player_name}", username.clone()), ("${version_name}", version_id.clone()), ("${game_directory}", game_path.to_string_lossy().to_string()), ("${assets_root}", game_path.join("assets").to_string_lossy().to_string()), ("${auth_access_token}", "0".into()), ("${auth_uuid}", "0".into()), ("${classpath}", classpath), ("${natives_directory}", game_path.join("versions").join(&version_id).join("natives").to_string_lossy().to_string())];
    let mut args = vec![format!("-Xmx{ram}M"), format!("-Xms{ram}M")];
    if let Some(profile_args) = profile.arguments { if let Some(jvm) = profile_args.jvm { args.extend(profile_values(&jvm.iter().flat_map(|v| v.get("values").into_iter().flat_map(|x| x.as_array().into_iter().flatten().cloned())).collect::<Vec<_>>(), &replacements)); } }
    args.extend(["-cp".into(), classpath, profile.main_class.unwrap_or_else(|| "cpw.mods.bootstraplauncher.BootstrapLauncher".into()), "--username".into(), username, "--version".into(), version_id, "--gameDir".into(), game_path.to_string_lossy().to_string(), "--server".into(), config.server_address, "--port".into(), config.server_port.to_string()]);
    Command::new(java).args(args).env("GORIZONT_SERVER", server).spawn().map_err(|e| format!("Не удалось запустить Java: {e}"))?; Ok(())
}

#[tauri::command]
async fn link_ip_to_account(username: String) -> Result<(), String> {
    if WEBHOOK_URL.is_empty() || WEBHOOK_TOKEN.is_empty() { return Err("Веб-хук не настроен в конфигурации лаунчера".into()); }
    Client::new().post(WEBHOOK_URL).bearer_auth(WEBHOOK_TOKEN).json(&serde_json::json!({"username": username})).send().await.map_err(|e| e.to_string())?.error_for_status().map_err(|e| e.to_string())?; Ok(())
}

fn main() { tauri::Builder::default().plugin(tauri_plugin_shell::init()).invoke_handler(tauri::generate_handler![download_and_extract_modpack, check_and_update_modpack, launch_minecraft, link_ip_to_account]).run(tauri::generate_context!()).expect("error while running Gorizont Launcher"); }
