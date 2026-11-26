//! CurseForge as a second source of mods. Everything is translated into the launcher's Modrinth structures, so the
//! install, version choice, "My mods", moderation and pack detection code is the same for both sources.
//! Project ids carry the prefix `cf-` ("cf-238222").

use super::{ModrinthFile, ModrinthHashes, ModrinthHit, ModrinthSearchResponse, ModrinthVersion};
use serde_json::Value;
use std::collections::HashMap;

const API: &str = "https://api.curseforge.com/v1";
/// A refused key is permanent for this build: CurseForge is then treated as absent where the launcher must not
/// depend on it (recognising hand-placed jars).
pub const KEY_REFUSED: &str = "CurseForge не принял ключ лаунчера";
const MINECRAFT: u32 = 432;
const MODS_CLASS: u32 = 6;
const NEOFORGE: u32 = 6;
pub const PREFIX: &str = "cf-";

/// The key is built into the launcher from the repository secret; the environment variable wins for local tests.
fn api_key() -> Option<String> {
    std::env::var("CURSEFORGE_API_KEY").ok()
        .or_else(|| option_env!("CURSEFORGE_API_KEY").map(str::to_string))
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

pub fn available() -> bool { api_key().is_some() }

pub fn is_curseforge(project_id: &str) -> bool { project_id.starts_with(PREFIX) }

fn numeric_id(project_id: &str) -> Result<u64, String> {
    project_id.strip_prefix(PREFIX).and_then(|id| id.parse().ok()).ok_or_else(|| "Некорректный идентификатор мода CurseForge".to_string())
}

async fn send(request: reqwest::RequestBuilder) -> Result<Value, String> {
    let key = api_key().ok_or_else(|| "В этой сборке лаунчера нет ключа CurseForge".to_string())?;
    let response = request.header("x-api-key", key).header("Accept", "application/json").send().await
        .map_err(|e| format!("CurseForge недоступен: {e}"))?;
    let status = response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 { return Err(KEY_REFUSED.into()); }
    if !status.is_success() { return Err(format!("CurseForge вернул ошибку: {status}")); }
    response.json().await.map_err(|e| format!("Не удалось разобрать ответ CurseForge: {e}"))
}

fn text(value: &Value, key: &str) -> String { value.get(key).and_then(Value::as_str).unwrap_or("").to_string() }

fn icon(value: &Value) -> Option<String> {
    value.get("logo").and_then(|logo| logo.get("thumbnailUrl")).and_then(Value::as_str).filter(|u| u.starts_with("https://")).map(str::to_string)
}

fn hit_from(value: &Value) -> Option<ModrinthHit> {
    let id = value.get("id").and_then(Value::as_u64)?;
    let names = |key: &str| -> Vec<String> {
        value.get(key).and_then(Value::as_array).into_iter().flatten().map(|item| text(item, "name")).filter(|n| !n.is_empty()).collect()
    };
    Some(ModrinthHit {
        project_id: format!("{PREFIX}{id}"),
        slug: text(value, "slug"),
        title: text(value, "name"),
        description: text(value, "summary"),
        author: names("authors").into_iter().next().unwrap_or_default(),
        icon_url: icon(value),
        downloads: value.get("downloadCount").and_then(Value::as_f64).unwrap_or(0.0) as u64,
        follows: 0,
        categories: names("categories"),
        client_side: String::new(),
        server_side: String::new(),
        date_modified: value.get("dateModified").and_then(Value::as_str).map(str::to_string),
        website_url: value.get("links").and_then(|l| l.get("websiteUrl")).and_then(Value::as_str).filter(|u| u.starts_with("https://www.curseforge.com/")).map(str::to_string),
        // Some authors forbid downloads by third-party programs.
        downloadable: value.get("allowModDistribution").and_then(Value::as_bool) != Some(false),
    })
}

/// Search of mods for the pack's Minecraft version and NeoForge.
pub async fn search(client: &reqwest::Client, game_version: &str, query: &str, sort: Option<&str>, offset: u32, limit: u32) -> Result<ModrinthSearchResponse, String> {
    // CurseForge sort fields: 2 popularity, 6 total downloads, 11 release date.
    let sort_field = match sort { Some("downloads") => "6", Some("newest") => "11", _ => "2" };
    let parameters = [
        ("gameId", MINECRAFT.to_string()),
        ("classId", MODS_CLASS.to_string()),
        ("gameVersion", game_version.to_string()),
        ("modLoaderType", NEOFORGE.to_string()),
        ("searchFilter", query.to_string()),
        ("sortField", sort_field.to_string()),
        ("sortOrder", "desc".to_string()),
        ("index", offset.to_string()),
        ("pageSize", limit.to_string()),
    ];
    let reply = send(client.get(format!("{API}/mods/search")).query(&parameters)).await?;
    let hits = reply.get("data").and_then(Value::as_array).into_iter().flatten().filter_map(hit_from).collect();
    let total = reply.get("pagination").and_then(|p| p.get("totalCount")).and_then(Value::as_u64).unwrap_or(0).min(10_000) as u32;
    Ok(ModrinthSearchResponse { hits, total_hits: total, offset, limit })
}

/// A file of a CurseForge mod as a Modrinth-like version.
pub fn version_from(file: &Value) -> Option<ModrinthVersion> {
    let id = file.get("id").and_then(Value::as_u64)?;
    let mod_id = file.get("modId").and_then(Value::as_u64)?;
    let tags: Vec<String> = file.get("gameVersions").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
    // hashes: algo 1 = SHA-1, 2 = MD5
    let md5 = file.get("hashes").and_then(Value::as_array).into_iter().flatten()
        .find(|h| h.get("algo").and_then(Value::as_u64) == Some(2))
        .map(|h| text(h, "value")).filter(|h| !h.is_empty());
    let name = text(file, "displayName");
    Some(ModrinthVersion {
        id: id.to_string(),
        project_id: format!("{PREFIX}{mod_id}"),
        version_type: match file.get("releaseType").and_then(Value::as_u64) { Some(2) => "beta", Some(3) => "alpha", _ => "release" }.to_string(),
        date_published: text(file, "fileDate"),
        game_versions: tags.iter().filter(|t| t.starts_with(|c: char| c.is_ascii_digit())).cloned().collect(),
        loaders: if tags.iter().any(|t| t.eq_ignore_ascii_case("neoforge")) { vec!["neoforge".to_string()] } else { Vec::new() },
        version_number: name.clone(),
        name,
        files: vec![ModrinthFile {
            // Empty when the author forbids third-party downloads.
            url: text(file, "downloadUrl"),
            filename: text(file, "fileName"),
            primary: true,
            size: file.get("fileLength").and_then(Value::as_u64).unwrap_or(0),
            hashes: Some(ModrinthHashes { sha512: None, md5 }),
        }],
    })
}

pub async fn files(client: &reqwest::Client, game_version: &str, project_id: &str) -> Result<Vec<ModrinthVersion>, String> {
    let id = numeric_id(project_id)?;
    let loader = NEOFORGE.to_string();
    let reply = send(client.get(format!("{API}/mods/{id}/files")).query(&[("gameVersion", game_version), ("modLoaderType", loader.as_str()), ("pageSize", "50")])).await?;
    Ok(reply.get("data").and_then(Value::as_array).into_iter().flatten().filter_map(version_from).collect())
}

/// Mod descriptions in the shape the launcher keeps for its cards.
fn project_from(value: &Value) -> Option<(String, Value)> {
    let id = format!("{PREFIX}{}", value.get("id").and_then(Value::as_u64)?);
    Some((id.clone(), serde_json::json!({
        "id": id,
        "title": text(value, "name"),
        "description": text(value, "summary"),
        "icon_url": icon(value),
        "slug": text(value, "slug"),
    })))
}

pub async fn projects(client: &reqwest::Client, project_ids: &[String]) -> Result<HashMap<String, Value>, String> {
    let ids: Vec<u64> = project_ids.iter().filter_map(|id| numeric_id(id).ok()).collect();
    if ids.is_empty() { return Ok(HashMap::new()); }
    let reply = send(client.post(format!("{API}/mods")).json(&serde_json::json!({ "modIds": ids }))).await?;
    Ok(reply.get("data").and_then(Value::as_array).into_iter().flatten().filter_map(project_from).collect())
}

/// CurseForge's file fingerprint: MurmurHash2 (seed 1) of the content without tabs, line breaks and spaces.
pub fn fingerprint(bytes: &[u8]) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let data: Vec<u8> = bytes.iter().copied().filter(|b| !matches!(b, 9 | 10 | 13 | 32)).collect();
    let mut hash: u32 = 1 ^ (data.len() as u32);
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]).wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        hash = hash.wrapping_mul(M) ^ k;
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        for (index, byte) in rest.iter().enumerate() { hash ^= (*byte as u32) << (8 * index); }
        hash = hash.wrapping_mul(M);
    }
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(M);
    hash ^ (hash >> 15)
}

/// Which CurseForge files these fingerprints belong to.
pub async fn match_fingerprints(client: &reqwest::Client, fingerprints: &[u32]) -> Result<HashMap<u32, ModrinthVersion>, String> {
    if fingerprints.is_empty() { return Ok(HashMap::new()); }
    let reply = send(client.post(format!("{API}/fingerprints/{MINECRAFT}")).json(&serde_json::json!({ "fingerprints": fingerprints }))).await?;
    Ok(reply.get("data").and_then(|d| d.get("exactMatches")).and_then(Value::as_array).into_iter().flatten()
        .filter_map(|found| {
            let file = found.get("file")?;
            let print = u32::try_from(file.get("fileFingerprint").and_then(Value::as_u64)?).ok()?;
            Some((print, version_from(file)?))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_curseforge_file_becomes_a_version_with_its_loader_and_checksum() {
        let file = serde_json::json!({
            "id": 55, "modId": 238222, "displayName": "jei 19", "fileName": "jei.jar", "releaseType": 2,
            "fileDate": "2025-01-01T00:00:00Z", "fileLength": 10, "downloadUrl": null,
            "gameVersions": ["1.21.1", "NeoForge", "Client"],
            "hashes": [{"value": "aaa", "algo": 1}, {"value": "bbb", "algo": 2}]
        });
        let version = version_from(&file).unwrap();
        assert_eq!(version.project_id, "cf-238222");
        assert_eq!(version.version_type, "beta");
        assert_eq!(version.game_versions, vec!["1.21.1".to_string()]);
        assert_eq!(version.loaders, vec!["neoforge".to_string()]);
        assert!(version.files[0].url.is_empty(), "no link: the author forbids third-party downloads");
        assert_eq!(version.files[0].hashes.as_ref().unwrap().md5.as_deref(), Some("bbb"));
        assert!(is_curseforge("cf-1") && !is_curseforge("AANobbMI"));
        assert!(numeric_id("cf-1/../x").is_err());
    }

    #[test]
    fn fingerprint_ignores_whitespace() {
        assert_eq!(fingerprint(b"abcdefg"), fingerprint(b"ab cd\r\n\tefg"));
        assert_ne!(fingerprint(b"abcdefg"), fingerprint(b"abcdefh"));
    }

    /// Against the real CurseForge with the real key: search, files, descriptions and recognition of a downloaded
    /// file by its fingerprint (what protects hand-placed mods).
    #[test]
    #[ignore]
    fn curseforge_live() {
        assert!(available(), "no CurseForge key");
        tauri::async_runtime::block_on(async {
            let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).build().unwrap();
            let found = search(&client, "1.21.1", "jei", None, 0, 10).await.unwrap();
            assert!(!found.hits.is_empty() && found.total_hits > 0, "search finds mods");
            let hit = found.hits.iter().find(|h| h.downloadable).expect("a downloadable mod");
            let versions = files(&client, "1.21.1", &hit.project_id).await.unwrap();
            assert!(!versions.is_empty(), "the mod has NeoForge 1.21.1 files");
            assert!(versions.iter().all(|v| v.loaders == vec!["neoforge".to_string()] && v.game_versions.iter().any(|g| g == "1.21.1")));
            let described = projects(&client, &[hit.project_id.clone()]).await.unwrap();
            assert_eq!(described[&hit.project_id]["slug"].as_str(), Some(hit.slug.as_str()));
            let file = &versions.iter().find(|v| !v.files[0].url.is_empty()).expect("a file with a link").files[0];
            let bytes = client.get(&file.url).send().await.unwrap().error_for_status().unwrap().bytes().await.unwrap();
            let expected = file.hashes.as_ref().and_then(|h| h.md5.clone()).expect("md5");
            assert!(format!("{:x}", md5::compute(&bytes)).eq_ignore_ascii_case(&expected), "checksum matches");
            let print = fingerprint(&bytes);
            let matched = match_fingerprints(&client, &[print]).await.unwrap();
            assert_eq!(matched.get(&print).map(|v| v.project_id.clone()), Some(hit.project_id.clone()), "recognised by fingerprint");
        });
    }
}
