package com.gorizont.authplugin;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.Cancellable;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
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
 * The launcher sends signed registration/login requests there. A successful signed request opens a session for
 * the nickname FROM THE ADDRESS OF THAT REQUEST, so the player joins without /login only from that address.
 * Everybody else - third-party launchers and cracked clients - has to use /register and /login in game.
 *
 * Protection: brute-force lockouts by IP with escalating duration (shared with the API), sessions bound to
 * the IP, a login timeout, no actions before login, protection against taking over an online nickname,
 * password checks off the main thread, and passwords kept out of the server log.
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
    private long maxLockoutMinutes;
    private long launcherSessionMinutes;
    private boolean forceLoginOnJoin;
    private int loginTimeoutSeconds;
    private boolean bindSessionToIp;
    private boolean rememberIngameLogin;
    private boolean blockSameNameTakeover;
    private boolean hidePasswordsInLog;
    private Set<String> moderators = Set.of();

    // State
    private AccountStore accounts;
    private LauncherSessions sessions;
    private BruteForceGuard guard;
    private ModerationStore moderation;
    private AuthHttpServer httpServer;

    private final Set<String> authenticatedPlayers = ConcurrentHashMap.newKeySet();

    private ScheduledExecutorService scheduler;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        reloadLocalConfig();

        accounts = new AccountStore(getDataFolder(), passwordMinLength, getLogger());
        sessions = new LauncherSessions(getDataFolder(), launcherSessionMinutes, bindSessionToIp, getLogger());
        moderation = new ModerationStore(getDataFolder(), getLogger());

        getServer().getPluginManager().registerEvents(this, this);

        Objects.requireNonNull(getCommand("login")).setExecutor(new LoginCommand());
        Objects.requireNonNull(getCommand("register")).setExecutor(new RegisterCommand());
        Objects.requireNonNull(getCommand("logout")).setExecutor(new LogoutCommand());
        Objects.requireNonNull(getCommand("changepassword")).setExecutor(new ChangePasswordCommand());
        Objects.requireNonNull(getCommand("gorizontauth")).setExecutor(new AdminCommand());

        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> guard.cleanup(), 1, 1, TimeUnit.MINUTES);

        if (hidePasswordsInLog) {
            try {
                PasswordLogFilter.install();
            } catch (LinkageError | RuntimeException e) {
                getLogger().warning("Could not install the password log filter, commands with passwords may appear in the log: " + e);
            }
        }

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
        PasswordLogFilter.deactivate();
        getLogger().info("Gorizont Auth Plugin disabled!");
    }

    private void startApi() {
        try {
            httpServer = new AuthHttpServer(getLogger(), accounts, hmacSecret, signatureMaxSkewSeconds, rateLimitPerMinute, sessions, passwordMinLength, guard, moderation, moderators);
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
        config.addDefault("auth.maxLockoutMinutes", 1440);
        config.addDefault("auth.loginTimeoutSeconds", 60);
        config.addDefault("auth.bindSessionToIp", true);
        config.addDefault("auth.rememberIngameLogin", true);
        config.addDefault("auth.blockSameNameTakeover", true);
        config.addDefault("auth.hidePasswordsInLog", true);
        config.addDefault("auth.moderators", List.of("OgonickYT"));

        enableAuth = config.getBoolean("auth.enableAuth", true);
        apiHost = config.getString("auth.apiHost", "0.0.0.0");
        apiPort = config.getInt("auth.apiPort", 22754);
        hmacSecret = config.getString("auth.hmacSecret", "");
        signatureMaxSkewSeconds = config.getInt("auth.signatureMaxSkewSeconds", 60);
        rateLimitPerMinute = config.getInt("auth.rateLimitPerMinute", 10);
        passwordMinLength = Math.max(1, config.getInt("auth.passwordMinLength", 4));
        maxLoginAttempts = config.getInt("auth.maxLoginAttempts", 5);
        lockoutDurationMinutes = config.getLong("auth.lockoutDurationMinutes", 15);
        maxLockoutMinutes = config.getLong("auth.maxLockoutMinutes", 1440);
        launcherSessionMinutes = config.getLong("auth.launcherSessionMinutes", 720);
        forceLoginOnJoin = config.getBoolean("auth.forceLoginOnJoin", true);
        loginTimeoutSeconds = Math.max(0, config.getInt("auth.loginTimeoutSeconds", 60));
        bindSessionToIp = config.getBoolean("auth.bindSessionToIp", true);
        rememberIngameLogin = config.getBoolean("auth.rememberIngameLogin", true);
        blockSameNameTakeover = config.getBoolean("auth.blockSameNameTakeover", true);
        hidePasswordsInLog = config.getBoolean("auth.hidePasswordsInLog", true);
        moderators = config.getStringList("auth.moderators").stream().map(n -> n.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
        config.options().copyDefaults(true);
        saveConfig();

        guard = new BruteForceGuard(maxLoginAttempts, lockoutDurationMinutes, maxLockoutMinutes);
        if (sessions != null) sessions.setBindToIp(bindSessionToIp);
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
        config.set("auth.maxLockoutMinutes", 1440);
        config.set("auth.launcherSessionMinutes", 720);
        config.set("auth.forceLoginOnJoin", true);
        config.set("auth.loginTimeoutSeconds", 60);
        config.set("auth.bindSessionToIp", true);
        config.set("auth.rememberIngameLogin", true);
        config.set("auth.blockSameNameTakeover", true);
        config.set("auth.hidePasswordsInLog", true);
        config.set("auth.moderators", List.of("OgonickYT"));
        config.options().copyDefaults(true);
        saveConfig();
    }

    // ==================== HELPERS ====================

    private static String ipOf(Player player) {
        var address = player.getAddress();
        return address == null || address.getAddress() == null ? "unknown" : address.getAddress().getHostAddress();
    }

    private static String minutesLeft(long millis) {
        return String.valueOf(Math.max(1, (millis + 59_999L) / 60_000L));
    }

    // ==================== EVENTS ====================

    @EventHandler
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enableAuth) return;
        String nickname = event.getName();
        String ip = event.getAddress().getHostAddress();
        if (sessions.isAuthorized(nickname, ip)) {
            getLogger().info("Player " + nickname + " has a launcher session from this address");
        } else {
            getLogger().info("Player " + nickname + " has no launcher session from this address, /login or /register required");
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerLogin(PlayerLoginEvent event) {
        if (!enableAuth) return;
        Player player = event.getPlayer();
        String username = player.getName();
        String ip = event.getAddress().getHostAddress();

        if (!AccountStore.validNickname(username)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, PREFIX + "§cНик: 3-16 символов, латиница, цифры и _");
            return;
        }

        long locked = guard.lockRemainingMillis(ip);
        if (locked > 0) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER,
                PREFIX + "§cСлишком много неудачных попыток входа. Попробуйте через " + minutesLeft(locked) + " мин.");
            return;
        }

        // Without this check anybody could join under the nickname of an online player and the server would
        // kick the real one ("logged in from another location").
        if (blockSameNameTakeover) {
            Player online = Bukkit.getPlayerExact(username);
            if (online != null && online.isOnline() && !ipOf(online).equals(ip)) {
                event.disallow(PlayerLoginEvent.Result.KICK_OTHER, PREFIX + "§cИгрок с этим ником уже на сервере.");
                getLogger().warning("Refused a second connection for online nickname " + username + " from " + ip);
            }
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (!enableAuth) return;
        Player player = event.getPlayer();
        String username = player.getName();
        String key = username.toLowerCase();

        if (sessions.isAuthorized(username, ipOf(player))) {
            authenticatedPlayers.add(key);
            player.sendMessage(PREFIX + "§aВы вошли через Gorizont Launcher — авторизация пройдена.");
            return;
        }

        authenticatedPlayers.remove(key);
        if (forceLoginOnJoin) {
            // The client is not ready in PlayerJoinEvent yet, so the prompt is sent a little later and repeated.
            startLoginReminder(player);
        } else {
            sendLoginPrompt(player);
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        // Failed attempts belong to the IP and are deliberately NOT cleared here: reconnecting must not
        // give a fresh set of guesses.
        authenticatedPlayers.remove(event.getPlayer().getName().toLowerCase());
    }

    // ==================== LOGIN GATE ====================

    /** True while a player must still log in: only /login and /register are allowed. */
    private boolean needsLogin(Player player) {
        return enableAuth && forceLoginOnJoin && !authenticatedPlayers.contains(player.getName().toLowerCase());
    }

    private void sendLoginPrompt(Player player) {
        player.sendMessage(PREFIX + "§eВы вошли не через наш лаунчер, нужна регистрация на сервере.");
        player.sendMessage(PREFIX + "§fНовый аккаунт: §e/register <пароль> <пароль>");
        player.sendMessage(PREFIX + "§fУже регистрировались: §e/login <пароль>");
        player.sendMessage(PREFIX + "§7Без входа вы не сможете играть.");
    }

    private void startLoginReminder(Player player) {
        final String name = player.getName();
        new BukkitRunnable() {
            @Override
            public void run() {
                Player p = Bukkit.getPlayerExact(name);
                if (p == null || !p.isOnline() || !needsLogin(p)) {
                    cancel();
                    return;
                }
                sendLoginPrompt(p);
            }
        }.runTaskTimer(this, 40L, 200L); // first prompt after 2 s, then every 10 s

        if (loginTimeoutSeconds > 0) {
            new BukkitRunnable() {
                @Override
                public void run() {
                    Player p = Bukkit.getPlayerExact(name);
                    if (p != null && p.isOnline() && needsLogin(p)) {
                        p.kickPlayer(PREFIX + "§cВремя на вход вышло (" + loginTimeoutSeconds + " с). Зайдите снова и введите /login или /register.");
                    }
                }
            }.runTaskLater(this, loginTimeoutSeconds * 20L);
        }
    }

    private void denyUntilLogin(Player player, Cancellable event) {
        event.setCancelled(true);
        player.sendMessage(PREFIX + "§cСначала войдите: §e/login <пароль>§c или §e/register <пароль> <пароль>");
    }

    @EventHandler(ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (!needsLogin(player)) return;
        Location from = event.getFrom();
        Location to = event.getTo();
        if (to == null) return;
        if (from.getX() != to.getX() || from.getY() != to.getY() || from.getZ() != to.getZ()) {
            Location fixed = from.clone();
            fixed.setYaw(to.getYaw());
            fixed.setPitch(to.getPitch());
            event.setTo(fixed);
        }
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!needsLogin(player)) return;
        String cmd = event.getMessage().toLowerCase().split(" ")[0];
        if (cmd.equals("/login") || cmd.equals("/l") || cmd.equals("/register") || cmd.equals("/reg")) return;
        denyUntilLogin(player, event);
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onBlockBreak(BlockBreakEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onBlockPlace(BlockPlaceEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onDropItem(PlayerDropItemEvent event) {
        if (needsLogin(event.getPlayer())) denyUntilLogin(event.getPlayer(), event);
    }

    @EventHandler
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player p && needsLogin(p)) denyUntilLogin(p, event);
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamage(EntityDamageEvent event) {
        // Players who have not logged in cannot take damage (mobs, void, fire).
        if (event.getEntity() instanceof Player p && needsLogin(p)) event.setCancelled(true);
    }

    // ==================== COMMANDS ====================

    private abstract class PlayerCommand implements CommandExecutor, TabCompleter {
        protected Player asPlayer(CommandSender sender) {
            if (sender instanceof Player player) return player;
            sender.sendMessage(PREFIX + "§cТолько игроки могут использовать эту команду.");
            return null;
        }

        /** Password checks use BCrypt (about a quarter of a second): never run them on the main thread. */
        protected void async(Runnable work, Runnable onMainThread) {
            Bukkit.getScheduler().runTaskAsynchronously(GorizontAuthPlugin.this, () -> {
                work.run();
                Bukkit.getScheduler().runTask(GorizontAuthPlugin.this, onMainThread);
            });
        }

        protected boolean stillOnline(Player player) {
            Player current = Bukkit.getPlayerExact(player.getName());
            return current != null && current.isOnline();
        }

        @Override
        public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
            return Collections.emptyList();
        }
    }

    /** Applies a wrong password: counts it for the IP and kicks when the address becomes locked. */
    private void failedPassword(Player player, String ip) {
        boolean locked = guard.recordFailure(ip);
        if (locked) {
            player.kickPlayer(PREFIX + "§cСлишком много неудачных попыток. Попробуйте через " + minutesLeft(guard.lockRemainingMillis(ip)) + " мин.");
            getLogger().warning("Address " + ip + " locked out after wrong passwords (last nickname " + player.getName() + ")");
        } else {
            player.sendMessage(PREFIX + "§cНеверный пароль. Осталось попыток: " + guard.attemptsLeft(ip));
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
            final String username = player.getName();
            final String key = username.toLowerCase();
            final String ip = ipOf(player);
            if (authenticatedPlayers.contains(key)) {
                player.sendMessage(PREFIX + "§aВы уже авторизованы!");
                return true;
            }
            long locked = guard.lockRemainingMillis(ip);
            if (locked > 0) {
                player.sendMessage(PREFIX + "§cСлишком много неудачных попыток. Попробуйте через " + minutesLeft(locked) + " мин.");
                return true;
            }
            final String password = args[0];
            final AccountStore.LoginResult[] result = new AccountStore.LoginResult[1];
            async(() -> result[0] = accounts.login(username, password), () -> {
                if (!stillOnline(player)) return;
                switch (result[0]) {
                    case OK -> {
                        guard.recordSuccess(ip);
                        authenticatedPlayers.add(key);
                        if (rememberIngameLogin) sessions.authorize(username, ip);
                        player.sendMessage(PREFIX + "§aВход выполнен успешно! Добро пожаловать, " + username);
                        getLogger().info("Player " + username + " logged in with the in-game password");
                    }
                    case NOT_FOUND -> {
                        guard.recordFailure(ip);
                        player.sendMessage(PREFIX + "§cАккаунт не найден. Создайте его: §e/register <пароль> <пароль>");
                    }
                    case INVALID_PASSWORD, INVALID_INPUT -> failedPassword(player, ip);
                    default -> player.sendMessage(PREFIX + "§cОшибка сервера, попробуйте позже.");
                }
            });
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
            final String username = player.getName();
            final String key = username.toLowerCase();
            final String ip = ipOf(player);
            if (authenticatedPlayers.contains(key)) {
                player.sendMessage(PREFIX + "§aВы уже авторизованы!");
                return true;
            }
            final String password = args[0];
            if (!password.equals(args[1])) {
                player.sendMessage(PREFIX + "§cПароли не совпадают");
                return true;
            }
            if (password.length() < passwordMinLength) {
                player.sendMessage(PREFIX + "§cПароль должен быть не короче " + passwordMinLength + " символов");
                return true;
            }
            final AccountStore.RegisterResult[] result = new AccountStore.RegisterResult[1];
            async(() -> result[0] = accounts.register(username, password), () -> {
                if (!stillOnline(player)) return;
                switch (result[0]) {
                    case REGISTERED -> {
                        authenticatedPlayers.add(key);
                        if (rememberIngameLogin) sessions.authorize(username, ip);
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
            });
            return true;
        }
    }

    private class ChangePasswordCommand extends PlayerCommand {
        @Override
        public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
            Player player = asPlayer(sender);
            if (player == null) return true;
            final String username = player.getName();
            if (!authenticatedPlayers.contains(username.toLowerCase())) {
                player.sendMessage(PREFIX + "§cСначала войдите: §e/login <пароль>");
                return true;
            }
            if (args.length < 2) {
                player.sendMessage(PREFIX + "§cИспользование: /changepassword <старый пароль> <новый пароль>");
                return true;
            }
            final String ip = ipOf(player);
            long locked = guard.lockRemainingMillis(ip);
            if (locked > 0) {
                player.sendMessage(PREFIX + "§cСлишком много неудачных попыток. Попробуйте через " + minutesLeft(locked) + " мин.");
                return true;
            }
            if (args[1].length() < passwordMinLength) {
                player.sendMessage(PREFIX + "§cНовый пароль должен быть не короче " + passwordMinLength + " символов");
                return true;
            }
            final String oldPassword = args[0];
            final String newPassword = args[1];
            final AccountStore.LoginResult[] result = new AccountStore.LoginResult[1];
            async(() -> result[0] = accounts.changePassword(username, oldPassword, newPassword), () -> {
                if (!stillOnline(player)) return;
                switch (result[0]) {
                    case OK -> {
                        // Launchers that hold a token of the old password must sign in again.
                        sessions.revoke(username);
                        sessions.authorize(username, ip);
                        player.sendMessage(PREFIX + "§aПароль изменён.");
                        getLogger().info("Player " + username + " changed the password");
                    }
                    case INVALID_PASSWORD -> failedPassword(player, ip);
                    case NOT_FOUND -> player.sendMessage(PREFIX + "§cУ этого ника нет аккаунта на сервере (вход был через лаунчер). Создайте пароль: §e/register");
                    default -> player.sendMessage(PREFIX + "§cОшибка сервера, попробуйте позже.");
                }
            });
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
                sender.sendMessage(PREFIX + "§e/gorizontauth <reload|status|unlock <ip|игрок>|unregister <игрок>>");
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
                    sender.sendMessage("  Launcher sessions: " + sessions.size() + (bindSessionToIp ? " (привязаны к IP)" : " (БЕЗ привязки к IP)"));
                    sender.sendMessage("  Authenticated players: " + authenticatedPlayers.size());
                    sender.sendMessage("  Locked addresses: " + guard.lockedCount());
                    sender.sendMessage("  Moderators: " + moderators + ", blocked mods: " + moderation.blockedCount() + ", approved mods: " + moderation.approvedCount());
                    break;
                case "unlock": {
                    if (args.length < 2) {
                        sender.sendMessage(PREFIX + "§cИспользование: /gorizontauth unlock <ip|игрок>");
                        return true;
                    }
                    Player online = Bukkit.getPlayerExact(args[1]);
                    String ip = online != null ? ipOf(online) : args[1];
                    guard.unlock(ip);
                    sender.sendMessage(PREFIX + "§aАдрес " + ip + " разблокирован.");
                    break;
                }
                case "unregister": {
                    if (args.length < 2) {
                        sender.sendMessage(PREFIX + "§cИспользование: /gorizontauth unregister <игрок>");
                        return true;
                    }
                    boolean removed = accounts.remove(args[1]);
                    sessions.revoke(args[1]);
                    authenticatedPlayers.remove(args[1].toLowerCase());
                    sender.sendMessage(PREFIX + (removed ? "§aАккаунт " + args[1] + " удалён." : "§cАккаунта " + args[1] + " нет."));
                    getLogger().info(sender.getName() + " unregistered " + args[1] + " (" + (removed ? "removed" : "not found") + ")");
                    break;
                }
                default:
                    sender.sendMessage(PREFIX + "§cНеизвестная подкоманда. Доступные: reload, status, unlock, unregister");
            }
            return true;
        }

        @Override
        public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
            if (args.length == 1) {
                return Arrays.asList("reload", "status", "unlock", "unregister");
            }
            if (args.length == 2 && (args[0].equalsIgnoreCase("unlock") || args[0].equalsIgnoreCase("unregister"))) {
                return new ArrayList<>(Bukkit.getOnlinePlayers().stream().map(Player::getName).toList());
            }
            return Collections.emptyList();
        }
    }
}
