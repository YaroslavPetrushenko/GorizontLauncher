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
 * Remembers which nicknames were authorised by a successful, signed launcher login/registration,
 * for a limited time, together with the IP address the launcher request came from.
 *
 * A player joins without /login only if the nickname has a live session AND connects from that same
 * address (when binding is on, which is the default). Without the address check, anybody who knows a
 * launcher player's nickname could join under it with a cracked client for the whole session.
 * The sessions are stored on disk so a server restart does not force every launcher player to log in again.
 */
public final class LauncherSessions {

    private static final class Session {
        final long until;
        final String ip;
        Session(long until, String ip) { this.until = until; this.ip = ip == null ? "" : ip; }
    }

    private final Logger logger;
    private final Path file;
    private final long sessionMillis;
    private volatile boolean bindToIp;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public LauncherSessions(File dataFolder, long sessionMinutes, boolean bindToIp, Logger logger) {
        this.logger = logger;
        this.sessionMillis = Math.max(1, sessionMinutes) * 60_000L;
        this.bindToIp = bindToIp;
        this.file = new File(dataFolder, "launcher_sessions.json").toPath();
        load();
    }

    public void setBindToIp(boolean bindToIp) {
        this.bindToIp = bindToIp;
    }

    private static String key(String nickname) {
        return nickname.toLowerCase(Locale.ROOT);
    }

    /** Opens a session for the nickname, valid from the given address. */
    public void authorize(String nickname, String ip) {
        if (nickname == null || nickname.isBlank()) return;
        sessions.put(key(nickname), new Session(System.currentTimeMillis() + sessionMillis, ip));
        save();
    }

    /**
     * True if the nickname has a live session. When binding is on and {@code ip} is given, the address must
     * be the one the session was opened from. Pass {@code null} to ignore the address.
     */
    public boolean isAuthorized(String nickname, String ip) {
        if (nickname == null || nickname.isBlank()) return false;
        Session session = sessions.get(key(nickname));
        if (session == null) return false;
        if (session.until <= System.currentTimeMillis()) {
            sessions.remove(key(nickname));
            save();
            return false;
        }
        if (bindToIp && ip != null && !ip.equals(session.ip)) return false;
        return true;
    }

    public void forget(String nickname) {
        if (nickname == null) return;
        if (sessions.remove(key(nickname)) != null) save();
    }

    public int size() {
        long now = System.currentTimeMillis();
        sessions.values().removeIf(s -> s.until <= now);
        return sessions.size();
    }

    private void load() {
        if (!Files.exists(file)) return;
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(text).getAsJsonObject();
            // The old format (nickname -> expiry only, no address) is dropped on purpose: such sessions
            // cannot be tied to an address and would be exactly the hole this class closes.
            JsonObject entries = root.has("sessions") ? root.getAsJsonObject("sessions") : new JsonObject();
            long now = System.currentTimeMillis();
            for (String nickname : entries.keySet()) {
                JsonObject entry = entries.getAsJsonObject(nickname);
                long until = entry.get("until").getAsLong();
                String ip = entry.has("ip") ? entry.get("ip").getAsString() : "";
                if (until > now) sessions.put(key(nickname), new Session(until, ip));
            }
            logger.info("Loaded " + sessions.size() + " launcher session(s)");
        } catch (IOException | RuntimeException e) {
            logger.warning("Failed to read launcher_sessions.json: " + e.getMessage());
        }
    }

    private synchronized void save() {
        try {
            JsonObject entries = new JsonObject();
            long now = System.currentTimeMillis();
            sessions.forEach((nickname, session) -> {
                if (session.until > now) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("until", session.until);
                    entry.addProperty("ip", session.ip);
                    entries.add(nickname, entry);
                }
            });
            JsonObject root = new JsonObject();
            root.addProperty("schemaVersion", 2);
            root.add("sessions", entries);

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
