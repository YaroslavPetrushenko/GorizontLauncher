package com.gorizont.authplugin;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.logging.Logger;

/**
 * Server-wide mod moderation shared by every launcher.
 *
 * <ul>
 *   <li><b>blocked</b>: Modrinth project ids that disappear from the mod search of all players and cannot be
 *       installed.</li>
 *   <li><b>approved</b>: SHA-256 of mod jars that players may keep in their mods folder across modpack updates.</li>
 * </ul>
 * Only configured moderators can change the lists (checked by {@link AuthHttpServer}); everybody can read them.
 */
public final class ModerationStore {

    private static final Pattern PROJECT_ID = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");

    private final Logger logger;
    private final Path file;
    /** key -> human readable title, kept so the moderator sees names in the lists. */
    private final Map<String, String> blocked = new LinkedHashMap<>();
    private final Map<String, String> approved = new LinkedHashMap<>();

    public ModerationStore(File dataFolder, Logger logger) {
        this.logger = logger;
        this.file = new File(dataFolder, "moderation.json").toPath();
        load();
    }

    public static boolean validProjectId(String value) {
        return value != null && PROJECT_ID.matcher(value).matches();
    }

    public static boolean validSha256(String value) {
        return value != null && SHA256.matcher(value).matches();
    }

    /** Applies one moderator decision. Returns false for an unknown action or an invalid key. */
    public synchronized boolean apply(String action, String key, String title) {
        String safeTitle = title == null ? "" : title.length() > 120 ? title.substring(0, 120) : title;
        switch (action) {
            case "block" -> {
                if (!validProjectId(key)) return false;
                blocked.put(key, safeTitle);
            }
            case "unblock" -> {
                if (!validProjectId(key)) return false;
                blocked.remove(key);
            }
            case "approve" -> {
                String hash = key == null ? "" : key.toLowerCase();
                if (!validSha256(hash)) return false;
                approved.put(hash, safeTitle);
            }
            case "unapprove" -> {
                String hash = key == null ? "" : key.toLowerCase();
                if (!validSha256(hash)) return false;
                approved.remove(hash);
            }
            default -> {
                return false;
            }
        }
        save();
        return true;
    }

    /** Snapshot sent to launchers: {"blocked":[ids],"approved":[sha256],"titles":{key:title}}. */
    public synchronized JsonObject snapshot() {
        JsonObject root = new JsonObject();
        JsonArray blockedArray = new JsonArray();
        JsonArray approvedArray = new JsonArray();
        JsonObject titles = new JsonObject();
        blocked.forEach((key, title) -> { blockedArray.add(key); titles.addProperty(key, title); });
        approved.forEach((key, title) -> { approvedArray.add(key); titles.addProperty(key, title); });
        root.add("blocked", blockedArray);
        root.add("approved", approvedArray);
        root.add("titles", titles);
        return root;
    }

    public synchronized int blockedCount() { return blocked.size(); }

    public synchronized int approvedCount() { return approved.size(); }

    private void load() {
        if (!Files.exists(file)) return;
        try {
            JsonObject root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
            readMap(root, "blocked", blocked);
            readMap(root, "approved", approved);
            logger.info("Loaded moderation: " + blocked.size() + " blocked, " + approved.size() + " approved");
        } catch (IOException | RuntimeException e) {
            logger.warning("Failed to read moderation.json: " + e.getMessage());
        }
    }

    private static void readMap(JsonObject root, String name, Map<String, String> target) {
        if (!root.has(name)) return;
        JsonObject entries = root.getAsJsonObject(name);
        for (String key : entries.keySet()) target.put(key, entries.get(key).getAsString());
    }

    private void save() {
        try {
            JsonObject root = new JsonObject();
            root.addProperty("schemaVersion", 1);
            JsonObject blockedObject = new JsonObject();
            blocked.forEach(blockedObject::addProperty);
            JsonObject approvedObject = new JsonObject();
            approved.forEach(approvedObject::addProperty);
            root.add("blocked", blockedObject);
            root.add("approved", approvedObject);

            Path parent = file.getParent();
            if (parent != null) Files.createDirectories(parent);
            Path temp = file.resolveSibling("moderation.json.tmp");
            Files.writeString(temp, root.toString(), StandardCharsets.UTF_8);
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException e) {
            logger.severe("Failed to save moderation.json: " + e.getMessage());
        }
    }
}
