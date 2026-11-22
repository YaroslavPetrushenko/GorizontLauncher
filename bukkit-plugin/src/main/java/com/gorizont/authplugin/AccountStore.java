package com.gorizont.authplugin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.mindrot.jbcrypt.BCrypt;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Accounts of the server-side auth plugin.
 *
 * Passwords are stored only as BCrypt hashes (cost 12) in {@code accounts.json}
 * next to the plugin config. The file is written atomically: a temporary file is
 * filled first and then moved over the old one, so a crash never leaves a broken store.
 */
public final class AccountStore {

    /** Result of a registration request. */
    public enum RegisterResult { REGISTERED, ALREADY_EXISTS, INVALID_INPUT, ERROR }

    /** Result of a login check. */
    public enum LoginResult { OK, INVALID_PASSWORD, NOT_FOUND, INVALID_INPUT, ERROR }

    private static final class Account {
        String nickname;
        String hash;
        String createdAt;
    }

    private final Logger logger;
    private final Path file;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final Map<String, Account> accounts = new LinkedHashMap<>();
    private final int passwordMinLength;

    public AccountStore(File dataFolder, int passwordMinLength, Logger logger) {
        this.logger = logger;
        this.passwordMinLength = Math.max(1, passwordMinLength);
        this.file = new File(dataFolder, "accounts.json").toPath();
        load();
    }

    /** Valid Minecraft nickname: 3-16 chars, letters, digits, underscore. */
    public static boolean validNickname(String nickname) {
        return nickname != null && nickname.matches("^[A-Za-z0-9_]{3,16}$");
    }

    private static String key(String nickname) {
        return nickname.toLowerCase(Locale.ROOT);
    }

    public synchronized int size() {
        return accounts.size();
    }

    public synchronized RegisterResult register(String nickname, String password) {
        if (!validNickname(nickname) || password == null || password.length() < passwordMinLength) {
            return RegisterResult.INVALID_INPUT;
        }
        String key = key(nickname);
        if (accounts.containsKey(key)) {
            return RegisterResult.ALREADY_EXISTS;
        }
        try {
            Account account = new Account();
            account.nickname = nickname;
            account.hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
            account.createdAt = java.time.Instant.now().toString();
            accounts.put(key, account);
            save();
            return RegisterResult.REGISTERED;
        } catch (RuntimeException | IOException e) {
            logger.severe("Failed to store account " + nickname + ": " + e.getMessage());
            accounts.remove(key);
            return RegisterResult.ERROR;
        }
    }

    public synchronized LoginResult login(String nickname, String password) {
        if (!validNickname(nickname) || password == null || password.isEmpty()) {
            return LoginResult.INVALID_INPUT;
        }
        Account account = accounts.get(key(nickname));
        if (account == null) {
            // Keep the timing comparable with a real check so nicknames cannot be probed by latency.
            BCrypt.checkpw(password, BCrypt.hashpw("timing-placeholder", BCrypt.gensalt(12)));
            return LoginResult.NOT_FOUND;
        }
        try {
            return BCrypt.checkpw(password, account.hash) ? LoginResult.OK : LoginResult.INVALID_PASSWORD;
        } catch (RuntimeException e) {
            logger.severe("Failed to verify password for " + nickname + ": " + e.getMessage());
            return LoginResult.ERROR;
        }
    }

    synchronized boolean exists(String nickname) {
        return accounts.containsKey(key(nickname));
    }

    private void load() {
        if (!Files.exists(file)) return;
        try {
            String text = Files.readString(file, StandardCharsets.UTF_8);
            JsonObject root = JsonParser.parseString(text).getAsJsonObject();
            JsonArray list = root.has("accounts") ? root.getAsJsonArray("accounts") : new JsonArray();
            for (JsonElement element : list) {
                if (!element.isJsonObject()) continue;
                JsonObject entry = element.getAsJsonObject();
                if (!entry.has("nickname") || !entry.has("hash")) continue;
                Account account = new Account();
                account.nickname = entry.get("nickname").getAsString();
                account.hash = entry.get("hash").getAsString();
                account.createdAt = entry.has("createdAt") ? entry.get("createdAt").getAsString() : "";
                accounts.put(key(account.nickname), account);
            }
            logger.info("Loaded " + accounts.size() + " account(s)");
        } catch (IOException | RuntimeException e) {
            logger.severe("Failed to read accounts.json: " + e.getMessage());
        }
    }

    private void save() throws IOException {
        JsonArray list = new JsonArray();
        for (Account account : accounts.values()) {
            JsonObject entry = new JsonObject();
            entry.addProperty("nickname", account.nickname);
            entry.addProperty("hash", account.hash);
            entry.addProperty("createdAt", account.createdAt);
            list.add(entry);
        }
        JsonObject root = new JsonObject();
        root.addProperty("schemaVersion", 1);
        root.add("accounts", list);

        Path parent = file.getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temp = file.resolveSibling("accounts.json.tmp");
        Files.writeString(temp, gson.toJson(root), StandardCharsets.UTF_8);
        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
    }
}
