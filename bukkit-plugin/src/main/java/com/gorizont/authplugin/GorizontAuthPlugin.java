package com.gorizont.authplugin;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * Server-side authentication for Gorizont Launcher.
 *
 * The plugin owns the account database and the HTTP API on the launcher port (default 22754).
 * The launcher sends signed registration/login requests there. A successful signed request marks
 * the nickname as launcher-authorised, so that player joins without /login. Everybody else —
 * third-party launchers and cracked clients — has to use /register and /login in game.
 */
public class GorizontAuthPlugin extends JavaPlugin implements Listener {

    private static final String PREFIX = "§8[§bGorizont§8] §r";

    // Configuration
    private boolean enableAuth;
    private String apiHost;
    private int apiPort;
    private String hmacSecret;
    private int signatureMaxSkewSeconds;
    private int rateLimitPerMinute;
    private int passwordMinLength;
    private int maxLoginAttempts;
    private long lockoutDurationMinutes;
    private long launcherSessionMinutes;
    private boolean forceLoginOnJoin;

    // State
    private AccountStore accounts;
    private LauncherSessions sessions;
    private AuthHttpServer httpServer;

    private final Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, Long> lockedUntil = new ConcurrentHashMap<>();
    private final Set<String> authenticatedPlayers = ConcurrentHashMap.newKeySet();

    private ScheduledExecutorService scheduler;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        reloadLocalConfig();

        accounts = new AccountStore(getDataFolder(), passwordMinLength, getLogger());
        sessions = new LauncherSessions(getDataFolder(), launcherSessionMinutes, getLogger());

        getServer().getPluginManager().registerEvents(this, this);

        Objects.requireNonNull(getCommand("login")).setExecutor(new LoginCommand());
        Objects.requireNonNull(getCommand("register")).setExecutor(new RegisterCommand());
        Objects.requireNonNull(getCommand("logout")).setExecutor(new LogoutCommand());
        Objects.requireNonNull(getCommand("gorizontauth")).setExecutor(new AdminCommand());

        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::cleanupExpiredLocks, 1, 1, TimeUnit.MINUTES);

        startApi();

        getLogger().info("Gorizont Auth Plugin enabled!");
        getLogger().info("Auth Enabled: " + enableAuth);
        getLogger().info("Accounts: " + accounts.size());
        getLogger().info("HMAC signing: " + (hmacSecret != null && !hmacSecret.isEmpty() ? "SET" : "NOT SET (launcher API will reject requests)"));
    }

    @Override
    public void onDisable() {
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        getLogger().info("Gorizont Auth Plugin disabled!");
    }

    private void startApi() {
        try {
            httpServer = new AuthHttpServer(getLogger(), accounts, hmacSecret, signatureMaxSkewSeconds, rateLimitPerMinute, sessions, passwordMinLength);
            httpServer.start(apiHost, apiPort);
            if (!httpServer.isSigningConfigured()) {
                getLogger().warning("auth.hmacSecret is empty — every launcher request will be rejected until it matches the launcher key");
            }
        } catch (IOException e) {
            getLogger().log(Level.SEVERE, "Failed to start the auth API on " + apiHost + ":" + apiPort, e);
            httpServer = null;
        }
    }

    private void reloadLocalConfig() {
        reloadConfig();
        FileConfiguration config = getConfig();
        enableAuth = config.getBoolean("auth.enableAuth", true);
        apiHost = config.getString("auth.apiHost", "0.0.0.0");
        apiPort = config.getInt("auth.apiPort", 22754);
        hmacSecret = config.getString("auth.hmacSecret", "");
        signatureMaxSkewSeconds = config.getInt("auth.signatureMaxSkewSeconds", 60);
        rateLimitPerMinute = config.getInt("auth.rateLimitPerMinute", 10);
        passwordMinLength = Math.max(1, config.getInt("auth.passwordMinLength", 4));
        maxLoginAttempts = config.getInt("auth.maxLoginAttempts", 5);
        lockoutDurationMinutes = config.getLong("auth.lockoutDurationMinutes", 15);
        launcherSessionMinutes = config.getLong("auth.launcherSessionMinutes", 720);
        forceLoginOnJoin = config.getBoolean("auth.forceLoginOnJoin", true);
        config.options().copyDefaults(true);
        saveConfig();
    }

    @Override
    public void saveDefaultConfig() {
        File configFile = new File(getDataFolder(), "config.yml");
        if (configFile.exists()) return;
        FileConfiguration config = getConfig();
        config.set("auth.enableAuth", true);
        config.set("auth.apiHost", "0.0.0.0");
        config.set("auth.apiPort", 22754);
        config.set("auth.hmacSecret", "");
        config.set("auth.signatureMaxSkewSeconds", 60);
        config.set("auth.rateLimitPerMinute", 10);
        config.set("auth.passwordMinLength", 4);
        config.set("auth.maxLoginAttempts", 5);
        config.set("auth.lockoutDurationMinutes", 15);
        config.set("auth.launcherSessionMinutes", 720);
        config.set("auth.forceLoginOnJoin", true);
        config.options().copyDefaults(true);
        saveConfig();
    }

    // ==================== EVENTS ====================

    @EventHandler
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enableAuth) return;
        String nickname = event.getName();
        // The session was created by a signed launcher login, so no in-game password is needed.
        // It is checked here, before the player is spawned, and consumed on join.
        if (sessions.isAuthorized(nickname)) {
            getLogger().info("Player " + nickname + " authorised by launcher session");
        } else {
            getLogger().info("Player " + nickname + " has no launcher session, /login or /register required");
        }
    }

    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        if (!enableAuth) return;
        String username = event.getPlayer().getName();
        if (isLockedOut(username)) {
            long remaining = Math.max(1, (lockedUntil.get(username.toLowerCase()) - System.currentTimeMillis()) / 1000 / 60);
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                PREFIX + "§cСлишком много неудачных попыток входа. Попробуйте через " + remaining + " мин.");
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (!enableAuth) return;
        Player player = event.getPlayer();
        String username = player.getName();
        String key = username.toLowerCase();

        if (sessions.isAuthorized(username)) {
            authenticatedPlayers.add(key);
            player.sendMessage(PREFIX + "§aВы вошли через Gorizont Launcher — авторизация пройдена.");
            return;
        }

        authenticatedPlayers.remove(key);
        player.sendMessage(PREFIX + "§eВы вошли не через наш лаунчер, нужна регистрация на сервере.");
        player.sendMessage(PREFIX + "§fНовый аккаунт: §e/register <пароль> <пароль>");
        player.sendMessage(PREFIX + "§fУже регистрировались: §e/login <пароль>");
        if (forceLoginOnJoin) {
            player.sendMessage(PREFIX + "§7Без входа вы не сможете играть.");
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        String key = event.getPlayer().getName().toLowerCase();
        authenticatedPlayers.remove(key);
        loginAttempts.remove(key);
    }

    // ==================== RATE LIMITING ====================

    private boolean isLockedOut(String username) {
        String key = username.toLowerCase();
        Long until = lockedUntil.get(key);
        if (until != null && until > System.currentTimeMillis()) return true;
        if (until != null) {
            lockedUntil.remove(key);
            loginAttempts.remove(key);
        }
        return false;
    }

    private void recordFailedAttempt(String username) {
        String key = username.toLowerCase();
        int attempts = loginAttempts.merge(key, 1, Integer::sum);
        if (attempts >= maxLoginAttempts) {
            lockedUntil.put(key, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(lockoutDurationMinutes));
            getLogger().warning("Player " + username + " locked out for " + lockoutDurationMinutes + " minutes after " + attempts + " failed attempts");
        }
    }

    private void resetLoginAttempts(String username) {
        String key = username.toLowerCase();
        loginAttempts.remove(key);
        lockedUntil.remove(key);
    }

    private void cleanupExpiredLocks() {
        long now = System.currentTimeMillis();
        lockedUntil.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    // ==================== COMMANDS ====================

    private abstract class PlayerCommand implements CommandExecutor, TabCompleter {
        protected Player asPlayer(CommandSender sender) {
            if (sender instanceof Player player) return player;
            sender.sendMessage(PREFIX + "§cТолько игроки могут использовать эту команду.");
            return null;
        }

        @Override
        public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
            return Collections.emptyList();
        }
    }

    private class LoginCommand extends PlayerCommand {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            Player player = asPlayer(sender);
            if (player == null) return true;
            if (args.length < 1) {
                player.sendMessage(PREFIX + "§cИспользование: /login <пароль>");
                return true;
            }
            String username = player.getName();
            if (authenticatedPlayers.contains(username.toLowerCase())) {
                player.sendMessage(PREFIX + "§aВы уже авторизованы!");
                return true;
            }
            if (isLockedOut(username)) {
                long remaining = Math.max(1, (lockedUntil.get(username.toLowerCase()) - System.currentTimeMillis()) / 1000 / 60);
                player.sendMessage(PREFIX + "§cСлишком много неудачных попыток. Попробуйте через " + remaining + " мин.");
                return true;
            }
            String password = args[0];
            AccountStore.LoginResult result = accounts.login(username, password);
            switch (result) {
                case OK -> {
                    resetLoginAttempts(username);
                    authenticatedPlayers.add(username.toLowerCase());
                    player.sendMessage(PREFIX + "§aВход выполнен успешно! Добро пожаловать, " + username);
                    getLogger().info("Player " + username + " logged in with the in-game password");
                }
                case INVALID_PASSWORD, INVALID_INPUT -> {
                    recordFailedAttempt(username);
                    int remaining = maxLoginAttempts - loginAttempts.getOrDefault(username.toLowerCase(), 0);
                    player.sendMessage(PREFIX + "§cНеверный пароль. Осталось попыток: " + Math.max(0, remaining));
                }
                case NOT_FOUND -> {
                    recordFailedAttempt(username);
                    player.sendMessage(PREFIX + "§cНеверный пароль. Осталось попыток: "
                        + Math.max(0, maxLoginAttempts - loginAttempts.getOrDefault(username.toLowerCase(), 0)));
                }
                default -> player.sendMessage(PREFIX + "§cОшибка сервера, попробуйте позже.");
            }
            return true;
        }
    }

    private class RegisterCommand extends PlayerCommand {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            Player player = asPlayer(sender);
            if (player == null) return true;
            if (args.length < 2) {
                player.sendMessage(PREFIX + "§cИспользование: /register <пароль> <подтверждение>");
                return true;
            }
            String username = player.getName();
            if (authenticatedPlayers.contains(username.toLowerCase())) {
                player.sendMessage(PREFIX + "§aВы уже авторизованы!");
                return true;
            }
            String password = args[0];
            String confirmPassword = args[1];
            if (!password.equals(confirmPassword)) {
                player.sendMessage(PREFIX + "§cПароли не совпадают");
                return true;
            }
            if (password.length() < passwordMinLength) {
                player.sendMessage(PREFIX + "§cПароль должен быть не короче " + passwordMinLength + " символов");
                return true;
            }
            AccountStore.RegisterResult result = accounts.register(username, password);
            switch (result) {
                case REGISTERED -> {
                    resetLoginAttempts(username);
                    authenticatedPlayers.add(username.toLowerCase());
                    sessions.authorize(username);
                    player.sendMessage(PREFIX + "§aРегистрация успешна! Вы вошли как " + username);
                    getLogger().info("Player " + username + " registered");
                }
                case ALREADY_EXISTS -> {
                    player.sendMessage(PREFIX + "§cТакой ник уже зарегистрирован. Используйте /login <пароль>");
                    getLogger().info("Registration refused for " + username + ": nickname taken");
                }
                case INVALID_INPUT -> player.sendMessage(PREFIX
                    + "§cНик: 3-16 символов (латиница, цифры, _); пароль не короче " + passwordMinLength + " символов");
                default -> player.sendMessage(PREFIX + "§cОшибка сервера, попробуйте позже.");
            }
            return true;
        }
    }

    private class LogoutCommand extends PlayerCommand {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            Player player = asPlayer(sender);
            if (player == null) return true;
            String key = player.getName().toLowerCase();
            authenticatedPlayers.remove(key);
            sessions.forget(player.getName());
            player.sendMessage(PREFIX + "§aВы вышли из аккаунта. Используйте /login для повторного входа.");
            getLogger().info("Player " + player.getName() + " logged out");
            return true;
        }
    }

    private class AdminCommand extends PlayerCommand {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            if (!sender.hasPermission("gorizontauth.admin")) {
                sender.sendMessage(PREFIX + "§cНет прав.");
                return true;
            }
            if (args.length < 1) {
                sender.sendMessage(PREFIX + "§e/gorizontauth <reload|status|unlock <player>>");
                return true;
            }
            switch (args[0].toLowerCase()) {
                case "reload":
                    if (httpServer != null) httpServer.stop();
                    reloadLocalConfig();
                    startApi();
                    sender.sendMessage(PREFIX + "§aКонфиг перезагружен. API: " + apiHost + ":" + apiPort);
                    break;
                case "status":
                    sender.sendMessage(PREFIX + "§eСтатус плагина:");
                    sender.sendMessage("  Auth enabled: " + enableAuth);
                    sender.sendMessage("  API: " + apiHost + ":" + apiPort + (httpServer == null ? " (не запущен)" : " (работает)"));
                    sender.sendMessage("  HMAC secret: " + (hmacSecret != null && !hmacSecret.isEmpty() ? "SET" : "NOT SET"));
                    sender.sendMessage("  Accounts: " + accounts.size());
                    sender.sendMessage("  Launcher sessions: " + sessions.size());
                    sender.sendMessage("  Authenticated players: " + authenticatedPlayers.size());
                    sender.sendMessage("  Locked players: " + lockedUntil.size());
                    break;
                case "unlock":
                    if (args.length < 2) {
                        sender.sendMessage(PREFIX + "§cИспользование: /gorizontauth unlock <player>");
                        return true;
                    }
                    String target = args[1].toLowerCase();
                    lockedUntil.remove(target);
                    loginAttempts.remove(target);
                    sender.sendMessage(PREFIX + "§aИгрок " + target + " разблокирован.");
                    break;
                default:
                    sender.sendMessage(PREFIX + "§cНеизвестная подкоманда. Доступные: reload, status, unlock");
            }
            return true;
        }

        @Override
        public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
            if (args.length == 1) {
                return Arrays.asList("reload", "status", "unlock");
            }
            if (args.length == 2 && args[0].equalsIgnoreCase("unlock")) {
                return new ArrayList<>(Bukkit.getOnlinePlayers().stream().map(Player::getName).toList());
            }
            return Collections.emptyList();
        }
    }
}
