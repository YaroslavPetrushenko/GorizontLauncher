package com.gorizont.authplugin;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * HTTP API of the auth plugin, listening on the launcher port (default 22754).
 *
 * The launcher signs every request with HMAC-SHA256 over {@code t + "\n" + nonce + "\n" + body}
 * and sends {@code X-Gorizont-Signature: t=<unix>,n=<nonce>,v1=<hex>}. Requests older than
 * {@link #maxSkewSeconds} and reused nonces are rejected, so a captured request cannot be replayed.
 *
 * Honest limitation: the shared key ships inside the launcher, so a determined attacker who
 * extracts the key can sign requests too. The signature protects against random/accidental
 * requests, not against a targeted reverse-engineering attack.
 */
public final class AuthHttpServer {

    private static final String SIGNATURE_HEADER = "X-Gorizont-Signature";
    private static final long NONCE_TTL_MS = 5 * 60 * 1000L;

    private final Logger logger;
    private final BruteForceGuard guard;
    private final AccountStore accounts;
    private final String hmacSecret;
    private final int maxSkewSeconds;
    private final int rateLimitPerMinute;
    private final LauncherSessions sessions;
    private final int passwordMinLength;
    private final ModerationStore moderation;
    private final Set<String> moderators;

    private HttpServer server;
    private ExecutorService executor;

    private final Map<String, long[]> ipWindows = new ConcurrentHashMap<>();
    private final Map<String, Long> usedNonces = new ConcurrentHashMap<>();

    public AuthHttpServer(Logger logger, AccountStore accounts, String hmacSecret, int maxSkewSeconds,
                          int rateLimitPerMinute, LauncherSessions sessions, int passwordMinLength, BruteForceGuard guard,
                          ModerationStore moderation, Set<String> moderators) {
        this.logger = logger;
        this.moderation = moderation;
        this.moderators = moderators;
        this.guard = guard;
        this.accounts = accounts;
        this.hmacSecret = hmacSecret == null ? "" : hmacSecret;
        this.maxSkewSeconds = Math.max(5, maxSkewSeconds);
        this.rateLimitPerMinute = Math.max(1, rateLimitPerMinute);
        this.sessions = sessions;
        this.passwordMinLength = Math.max(1, passwordMinLength);
    }

    public boolean isSigningConfigured() {
        return !hmacSecret.isEmpty();
    }

    public void start(String host, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        executor = Executors.newFixedThreadPool(4);
        server.setExecutor(executor);
        server.createContext("/health", exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));
        server.createContext("/auth/register", this::handleRegister);
        server.createContext("/auth/login", this::handleLogin);
        server.createContext("/auth/refresh", this::handleRefresh);
        server.createContext("/auth/check-player", this::handleCheckPlayer);
        server.createContext("/mods/moderation", this::handleModerationList);
        server.createContext("/mods/moderate", this::handleModerate);
        server.start();
        logger.info("Auth API listening on " + host + ":" + port);
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    // ==================== HANDLERS ====================

    private void handleRegister(HttpExchange exchange) throws IOException {
        withSignedJson(exchange, (body, ip) -> {
            JsonObject json = body;
            String nickname = stringField(json, "nickname");
            String password = stringField(json, "password");
            AccountStore.RegisterResult result = accounts.register(nickname, password);
            JsonObject reply = new JsonObject();
            switch (result) {
                case REGISTERED -> {
                    reply.addProperty("status", "registered");
                    sessions.authorize(nickname, ip);
                    reply.addProperty("token", sessions.issueToken(nickname));
                }
                case ALREADY_EXISTS -> {
                    reply.addProperty("status", "already_exists");
                    reply.addProperty("error", "Ник уже зарегистрирован");
                }
                case INVALID_INPUT -> {
                    reply.addProperty("status", "invalid_input");
                    reply.addProperty("error", "Ник 3-16 символов (латиница, цифры, _), пароль не короче " + passwordMinLength + " символов");
                }
                case ERROR -> {
                    reply.addProperty("status", "error");
                    reply.addProperty("error", "Внутренняя ошибка сервера");
                }
            }
            return reply;
        });
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        withSignedJson(exchange, (body, ip) -> {
            String nickname = stringField(body, "nickname");
            String password = stringField(body, "password");
            long lockedMillis = guard.lockRemainingMillis(ip);
            if (lockedMillis > 0) {
                JsonObject lockedReply = new JsonObject();
                lockedReply.addProperty("status", "locked");
                lockedReply.addProperty("error", "Слишком много неудачных попыток. Повторите через " + Math.max(1, lockedMillis / 60_000L) + " мин.");
                return lockedReply;
            }
            AccountStore.LoginResult result = accounts.login(nickname, password);
            JsonObject reply = new JsonObject();
            switch (result) {
                case OK -> {
                    reply.addProperty("status", "ok");
                    guard.recordSuccess(ip);
                    sessions.authorize(nickname, ip);
                    reply.addProperty("token", sessions.issueToken(nickname));
                }
                case INVALID_PASSWORD -> {
                    guard.recordFailure(ip);
                    reply.addProperty("status", "invalid_password");
                    reply.addProperty("error", "Неверный пароль");
                }
                case NOT_FOUND -> {
                    guard.recordFailure(ip);
                    reply.addProperty("status", "not_found");
                    reply.addProperty("error", "Пользователь не найден");
                }
                case INVALID_INPUT -> {
                    reply.addProperty("status", "invalid_input");
                    reply.addProperty("error", "Некорректный ник или пароль");
                }
                case ERROR -> {
                    reply.addProperty("status", "error");
                    reply.addProperty("error", "Внутренняя ошибка сервера");
                }
            }
            return reply;
        });
    }

    /**
     * The launcher opens a fresh session at every game start: it shows the token it got at login. The session is
     * tied to the address of THIS request, which is the address the game then connects from. No password is needed
     * and none is stored in the launcher.
     */
    private void handleRefresh(HttpExchange exchange) throws IOException {
        withSignedJson(exchange, (body, ip) -> {
            String nickname = stringField(body, "nickname");
            String token = stringField(body, "token");
            JsonObject reply = new JsonObject();
            long lockedMillis = guard.lockRemainingMillis(ip);
            if (lockedMillis > 0) {
                reply.addProperty("status", "locked");
                reply.addProperty("error", "Слишком много неудачных попыток. Повторите через " + Math.max(1, lockedMillis / 60_000L) + " мин.");
                return reply;
            }
            if (token == null || token.isBlank()) {
                reply.addProperty("status", "invalid_token");
            } else if (sessions.verifyToken(nickname, token)) {
                sessions.authorize(nickname, ip);
                reply.addProperty("status", "ok");
            } else {
                guard.recordFailure(ip);
                reply.addProperty("status", "invalid_token");
            }
            return reply;
        });
    }

    private void handleCheckPlayer(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            respond(exchange, 405, "{\"authorized\":false,\"nickname\":\"\",\"reason\":\"method not allowed\"}");
            return;
        }
        String ip = remoteIp(exchange);
        if (!allowRequest(ip)) {
            respond(exchange, 200, "{\"authorized\":false,\"nickname\":\"\",\"reason\":\"rate limited\"}");
            return;
        }
        if (!verifySignature(exchange, "")) {
            respond(exchange, 200, "{\"authorized\":false,\"nickname\":\"\",\"reason\":\"invalid signature\"}");
            return;
        }
        String nickname = queryParam(exchange.getRequestURI().getRawQuery(), "nickname");
        JsonObject reply = new JsonObject();
        String safeNickname = nickname == null ? "" : nickname;
        reply.addProperty("nickname", safeNickname);
        if (safeNickname.isEmpty()) {
            reply.addProperty("authorized", false);
            reply.addProperty("reason", "nickname is required");
        } else {
            boolean authorized = sessions.isAuthorized(safeNickname, null);
            reply.addProperty("authorized", authorized);
            if (!authorized) {
                reply.addProperty("reason", "no launcher session for this nickname");
            }
        }
        respond(exchange, 200, reply.toString());
    }

    // ==================== MOD MODERATION ====================

    /** Public (signed) read of the server-wide lists: blocked Modrinth projects and approved mod hashes. */
    private void handleModerationList(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            respond(exchange, 405, "{\"error\":\"method not allowed\"}");
            return;
        }
        // No speed limit here: players refresh the lists often so that a block shows up at once. The request is
        // signed and the answer is a small cached list, so nothing is gained by throttling it.
        if (!verifySignature(exchange, "")) {
            respond(exchange, 401, "{\"error\":\"invalid signature\"}");
            return;
        }
        respond(exchange, 200, moderation.snapshot().toString());
    }

    /**
     * A moderator changes the lists. The nickname must be on the configured moderator list AND the request must
     * carry that account's password, which is checked like a normal login (same brute-force guard). The launcher
     * shows the controls only to moderators, but this check is the real protection.
     */
    private void handleModerate(HttpExchange exchange) throws IOException {
        withSignedJson(exchange, false, (body, ip) -> {
            JsonObject reply = new JsonObject();
            String nickname = stringField(body, "nickname");
            String password = stringField(body, "password");
            String action = stringField(body, "action");
            String key = stringField(body, "key");
            String title = stringField(body, "title");

            long lockedMillis = guard.lockRemainingMillis(ip);
            if (lockedMillis > 0) {
                reply.addProperty("status", "locked");
                reply.addProperty("error", "Слишком много неудачных попыток. Повторите через " + Math.max(1, lockedMillis / 60_000L) + " мин.");
                return reply;
            }
            if (!moderators.contains(nickname.toLowerCase(Locale.ROOT))) {
                guard.recordFailure(ip);
                reply.addProperty("status", "forbidden");
                reply.addProperty("error", "Управлять модами может только модератор");
                logger.warning("Moderation refused for non-moderator '" + nickname + "' from " + ip);
                return reply;
            }
            AccountStore.LoginResult login = accounts.login(nickname, password);
            if (login != AccountStore.LoginResult.OK) {
                guard.recordFailure(ip);
                reply.addProperty("status", login == AccountStore.LoginResult.ERROR ? "error" : "invalid_password");
                reply.addProperty("error", "Неверный пароль модератора");
                return reply;
            }
            if (!moderation.apply(action, key, title)) {
                reply.addProperty("status", "invalid_input");
                reply.addProperty("error", "Некорректное действие или идентификатор");
                return reply;
            }
            reply.addProperty("status", "ok");
            logger.info("Moderator " + nickname + " did '" + action + "' on " + key + (title.isEmpty() ? "" : " (" + title + ")"));
            return reply;
        });
    }

    // ==================== SIGNED JSON PLUMBING ====================

    private interface SignedHandler {
        JsonObject handle(JsonObject body, String ip) throws IOException;
    }

    private void withSignedJson(HttpExchange exchange, SignedHandler handler) throws IOException {
        withSignedJson(exchange, true, handler);
    }

    /** @param limited whether the per-IP request limit applies (moderation is not limited: blocking must be instant) */
    private void withSignedJson(HttpExchange exchange, boolean limited, SignedHandler handler) throws IOException {
        try {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                respond(exchange, 405, "{\"status\":\"error\",\"error\":\"method not allowed\"}");
                return;
            }
            String ip = remoteIp(exchange);
            if (limited && !allowRequest(ip)) {
                respond(exchange, 200, "{\"status\":\"error\",\"error\":\"Слишком много попыток, попробуйте позже\"}");
                return;
            }
            String bodyText = readBody(exchange);
            if (!verifySignature(exchange, bodyText)) {
                respond(exchange, 401, "{\"status\":\"error\",\"error\":\"Неверная подпись запроса\"}");
                return;
            }
            JsonObject body;
            try {
                body = JsonParser.parseString(bodyText.isEmpty() ? "{}" : bodyText).getAsJsonObject();
            } catch (RuntimeException e) {
                respond(exchange, 400, "{\"status\":\"error\",\"error\":\"Некорректный JSON\"}");
                return;
            }
            JsonObject reply = handler.handle(body, ip);
            respond(exchange, 200, reply.toString());
        } catch (RuntimeException e) {
            logger.severe("Request failed: " + e.getMessage());
            respond(exchange, 500, "{\"status\":\"error\",\"error\":\"Внутренняя ошибка сервера\"}");
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream input = exchange.getRequestBody()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Simple per-IP sliding window: rateLimitPerMinute requests per 60 seconds. */
    private boolean allowRequest(String ip) {
        long now = System.currentTimeMillis();
        long[] window = ipWindows.computeIfAbsent(ip, key -> new long[]{now, 0});
        synchronized (window) {
            if (now - window[0] >= 60_000L) {
                window[0] = now;
                window[1] = 0;
            }
            if (window[1] >= rateLimitPerMinute) return false;
            window[1]++;
            return true;
        }
    }

    /** Validates X-Gorizont-Signature against t, nonce and body; enforces skew and replay rules. */
    private boolean verifySignature(HttpExchange exchange, String body) {
        if (hmacSecret.isEmpty()) return false;
        String header = exchange.getRequestHeaders().getFirst(SIGNATURE_HEADER);
        if (header == null || header.isBlank()) return false;

        String timestamp = null;
        String nonce = null;
        String signature = null;
        for (String part : header.split(",")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length != 2) continue;
            switch (pair[0].trim()) {
                case "t" -> timestamp = pair[1].trim();
                case "n" -> nonce = pair[1].trim();
                case "v1" -> signature = pair[1].trim();
                default -> { }
            }
        }
        if (timestamp == null || nonce == null || signature == null) return false;
        if (nonce.length() < 8 || nonce.length() > 128) return false;

        long requestTime;
        try {
            requestTime = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            return false;
        }
        long now = System.currentTimeMillis() / 1000L;
        if (Math.abs(now - requestTime) > maxSkewSeconds) return false;

        long nowMs = System.currentTimeMillis();
        usedNonces.values().removeIf(seen -> nowMs - seen > NONCE_TTL_MS);
        if (usedNonces.putIfAbsent(nonce, nowMs) != null) return false;

        String canonical = requestTime + "\n" + nonce + "\n" + body;
        String expected = hmacHex(canonical);
        return expected != null && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            signature.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            logger.severe("HMAC failure: " + e.getMessage());
            return null;
        }
    }

    private static String stringField(JsonObject object, String name) {
        if (object == null || !object.has(name) || object.get(name).isJsonNull()) return "";
        try {
            return object.get(name).getAsString();
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String queryParam(String rawQuery, String name) {
        if (rawQuery == null || rawQuery.isEmpty()) return null;
        for (String part : rawQuery.split("&")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            if (!part.substring(0, eq).equals(name)) continue;
            return java.net.URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
        }
        return null;
    }

    private static String remoteIp(HttpExchange exchange) {
        var address = exchange.getRemoteAddress();
        return address == null ? "unknown" : address.getAddress().getHostAddress();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}
