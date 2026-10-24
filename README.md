# Gorizont Launcher

Tauri v2 + React launcher for NeoForge 1.21.1.

## Модель выпуска

Лаунчер выпускается один раз как Windows-приложение. После установки пользователям не нужно скачивать новый лаунчер при каждом обновлении модов: мы меняем только сборку Minecraft в GitHub Releases.

Репозиторий:

`https://github.com/YaroslavPetrushenko/GorizontLauncher`

Лаунчер запрашивает список опубликованных релизов GitHub и выбирает только тот релиз, где есть asset `modpack.zip`. Поэтому релизы самого лаунчера не будут ошибочно скачиваться как модпак.

### Первый выпуск лаунчера

Создайте тег вида `launcher-v1.0.0` и отправьте его в GitHub. Workflow автоматически соберёт Windows-лаунчер и опубликует ZIP с приложением.

```powershell
git tag launcher-v1.0.0
git push origin launcher-v1.0.0
```

### Как менять только сборку

1. Подготовьте папку сборки: моды, конфиги и `manifest.json`.
2. `manifest.json` должен лежать в корне ZIP и иметь формат из [modpack-manifest.example.json](E:\GorizontLauncher\modpack-manifest.example.json):

```json
{
  "schema_version": 1,
  "pack_id": "gorizont",
  "pack_version": "1.0.1",
  "minecraft_version": "1.21.1",
  "loader": { "type": "neoforge", "version": "248" }
}
```

3. Упакуйте содержимое папки в файл строго `modpack.zip`.
4. В GitHub откройте **Releases** → **Create a new release**.
5. Создайте тег сборки, например `pack-1.0.1`, прикрепите `modpack.zip` и нажмите **Publish release**.
6. Установленный лаунчер сам скачает ZIP, проверит `manifest.json`, версию Minecraft и NeoForge, а затем установит сборку.

Новый лаунчер игроку для этого не требуется. Если manifest отсутствует или версия загрузчика отличается от настроенной, установка остановится с понятной ошибкой.

Имя файла и репозиторий можно изменить в одном файле в корне проекта:

```json
// launcher.config.json
{
  "github_owner": "YaroslavPetrushenko",
  "github_repo": "GorizontLauncher",
  "modpack_asset": "modpack.zip",
  "expected_manifest": "manifest.json",
  "pack_id": "gorizont",
  "release_mode": "modpack-only",
  "minecraft_version": "1.21.1",
  "launch_version_id": "1.21.1-neoforge",
  "loader_type": "neoforge",
  "loader_version": "248",
  "server_address": "mc.gorizont.fun",
  "server_port": 20054
}
```

После изменения `launcher.config.json` нужно заново собрать лаунчер, потому что конфигурация встраивается в Rust-приложение при компиляции. Игроку достаточно скачать Windows-установщик один раз; обычные обновления pack-релизов скачиваются автоматически.

Если точного `modpack.zip` нет, лаунчер покажет ошибку и не будет скачивать исходный код репозитория. Это важно: ZIP самого лаунчера и ZIP сборки — разные файлы.

## Версия сборки

Для обновления сборки используйте новый тег релиза, например `pack-1.0.1`, `pack-1.0.2`. Лаунчер сохраняет тег скачанной сборки в настройках как `localVersion`. Пока тег не изменился, ZIP повторно не скачивается.

## Конфигурация webhook

Настройте `WEBHOOK_URL` и `WEBHOOK_TOKEN` в `src-tauri/src/main.rs` или вынесите их в безопасную build-time конфигурацию. Не коммитьте секретный токен в публичный GitHub-репозиторий.

AuthMe Reloaded остаётся серверной системой авторизации: лаунчер не проверяет пароль, первый вход выполняется через `/login`, а PremiumAuthBypass или аналогичный серверный плагин может использовать привязку IP.

## Запуск игры и Java

Игроку не нужно заранее устанавливать Java. При запуске лаунчер сначала ищет Java в `JAVA_HOME` и `PATH`. Если Java не найдена, он автоматически скачивает и кэширует Java 21 в `%LOCALAPPDATA%\\GorizontLauncher\\runtime`.

Для Minecraft 1.21.1 нужна Java 21. Версия Java 27 для этой сборки не требуется и не используется.

Путь `%APPDATA%/.minecraft` теперь корректно разворачивается в Windows-путь `%APPDATA%\\.minecraft`.

Если `modpack.zip` ещё не опубликован, запуск блокируется понятным сообщением: сначала нужно опубликовать сборку с `manifest.json` и клиентскими файлами.

## Запуск разработки

```powershell
npm install
npm run tauri dev
```
