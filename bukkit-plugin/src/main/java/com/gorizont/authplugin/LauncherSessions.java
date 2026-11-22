package com.gorizont.authplugin;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Remembers which nicknames were authorised by a successful, signed launcher
 * login/registration, for a limited time.
 *
 * A player whose nickname is in this list joins without /login. The list is stored on
 * disk so a server restart does not force every launcher player to log in again.
 */
public final class LauncherSessions {

    private final Logger logger;
    private final Path file;
    private final long sessionMillis;
    private final Map<String, Long> authorizedUntil = new ConcurrentHashMap<>();

    public LauncherSessions(File dataFolder, long sessionMinutes, Logger logger) {
        this.logger = logger;
        this.sessionMillis = Math.max(1, sessionMinutes) * 60_000L;
        this.file = new File(dataFolder, "launcher_sessions.json").toPath();
        load();
    }

    private static String key(String nickname) {
        return nickname.toLowerCase(Locale.ROOT);
    }

    public void authorize(String nickname) {
        if (nickname == null || nickname.isBlank()) return;
        authorizedUntil.put(key(nickname), System.currentTimeMillis() + sessionMillis);
        save();
    }

    public boolean isAuthorized(String nickname) {
        if (nickname == null || nickname.isBlank()) return false;
        Long until = authorizedUntil.get(key(nickname));
        if (until == null) return false;
        if (until <= System.currentTimeMillis()) {
            authorizedUntil.remove(key(nickname));
            save();
            return false;
        }
        return true;
    }

    public void forget(String nickname) {
        if (nickname == null) return;
        if (authorizedUntil.remove(key(nickname)) != null) save();
    }

    public int size() {
        long now = System.currentTimeMillis();
        authorizedUntil.values().removeIf(until -> until <= now);
        return authorizedUntil.size();
    }

    private void load() {
        if (!Files.exists(file)) return;
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(text).getAsJsonObject();
            JsonObject entries = root.has("authorizedUntil") ? root.getAsJsonObject("authorizedUntil") : new JsonObject();
            long now = System.currentTimeMillis();
            for (String nickname : entries.keySet()) {
                long until = entries.get(nickname).getAsLong();
                if (until > now) authorizedUntil.put(key(nickname), until);
            }
            logger.info("Loaded " + authorizedUntil.size() + " launcher session(s)");
        } catch (IOException | RuntimeException e) {
            logger.warning("Failed to read launcher_sessions.json: " + e.getMessage());
        }
    }

    private void save() {
        try {
            JsonObject entries = new JsonObject();
            long now = System.currentTimeMillis();
            long[] stamp = new long[]{now};
            authorizedUntil.forEach((nickname, until) -> {
                if (until > stamp[0]) entries.addProperty(nickname, until);
            });
            JsonObject root = new JsonObject();
            root.addProperty("schemaVersion", 1);
            root.add("authorizedUntil", entries);

            Path parent = file.getParent();
            if (parent != null) Files.createDirectories(parent);
            Path temp = file.resolveSibling("launcher_sessions.json.tmp");
            Files.writeString(temp, root.toString(), StandardCharsets.UTF_8);
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException e) {
            logger.warning("Failed to save launcher_sessions.json: " + e.getMessage());
        }
    }
}
