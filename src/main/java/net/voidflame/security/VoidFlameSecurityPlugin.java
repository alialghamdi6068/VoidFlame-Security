package net.voidflame.security;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.geysermc.cumulus.form.SimpleForm;
import org.geysermc.cumulus.response.SimpleFormResponse;
import org.geysermc.floodgate.api.FloodgateApi;

import net.voidflame.core.storage.StorageService;
import net.voidflame.core.api.AuditLogService;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.*;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.WorldCreator;
import org.bukkit.World;
import org.bukkit.generator.ChunkGenerator;
import org.bukkit.generator.WorldInfo;
import org.bukkit.generator.ChunkGenerator.ChunkData;
import org.bukkit.generator.ChunkGenerator.BiomeGrid;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;

public final class VoidFlameSecurityPlugin extends JavaPlugin implements Listener {
    private StorageService storage;
    private final ConcurrentHashMap<UUID, Deque<Long>> actionWindows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Long> joinTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Integer> captchaSlots = new ConcurrentHashMap<>();
    private final Set<UUID> checking = ConcurrentHashMap.newKeySet();
    private final Set<UUID> verified = ConcurrentHashMap.newKeySet();
    private final Set<UUID> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<UUID> rateLimitBypass = ConcurrentHashMap.newKeySet();
    private final Set<UUID> authenticated = ConcurrentHashMap.newKeySet();
    private final Set<UUID> authRequired = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<UUID, Integer> authAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Integer> captchaAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Long> captchaStarted = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Integer> riskScores = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Long> blockedUntil = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> violationCooldowns = new ConcurrentHashMap<>();
    private volatile int protectionLevel = 0;
    private volatile boolean enabled;
    private volatile boolean lockdown;
    private AuditLogService auditLogs;
    private World authWorld;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        enabled = getConfig().getBoolean("settings.enabled", true);
        lockdown = getConfig().getBoolean("settings.lockdown", false);
        if (!connectStorage()) {
            getLogger().severe("VoidFlame-Core storage service is unavailable.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        loadWhitelistAsync();
        // VoidFlameMC uses Minecraft's normal authentication. Local /login and /register are disabled.
        getServer().getPluginManager().registerEvents(this, this);
        getServer().getPluginManager().registerEvents(new SecurityDetectionListener(this), this);
        getServer().getPluginManager().registerEvents(new AdvancedProtectionListener(this), this);
        Objects.requireNonNull(getCommand("antibot")).setExecutor((sender, command, label, args) -> command(sender, args));
        Objects.requireNonNull(getCommand("antibot")).setTabCompleter((sender, command, alias, args) -> tabComplete(args));
        long decayTicks = Math.max(10L, getConfig().getLong("antibot.decay-seconds", 300L) * 20L);
        getServer().getScheduler().runTaskTimer(this, this::decayProtection, decayTicks, decayTicks);
        getLogger().info("VoidFlame-Security enabled: AntiBot + rate protection.");
    }

    private boolean connectStorage() {
        var registration = getServer().getServicesManager().getRegistration(StorageService.class);
        if (registration == null) return false;
        storage = registration.getProvider();
        var logs = getServer().getServicesManager().getRegistration(AuditLogService.class);
        auditLogs = logs == null ? null : logs.getProvider();
        return storage != null;
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID id = player.getUniqueId();
        long now = System.currentTimeMillis();
        joinTimes.put(id, now);
        bypassRateLimits(player);
        if (authEnabled() && !Bukkit.getOnlineMode()) prepareAuthentication(player);

        if (lockdown && !isSecurityTrusted(id)) {
            player.kickPlayer(color(getConfig().getString("messages.lockdown", "&cThe server is temporarily locked down by security protection.")));
            return;
        }
        if (!enabled || bypassCaptcha(player)) return;
        long blocked = blockedUntil.getOrDefault(id, 0L);
        if (blocked > now) {
            player.kickPlayer(getConfig().getString("messages.temporarily-blocked", "§cSecurity protection is active. Please try again later."));
            return;
        }
        storage.get("security", "verified:" + id).thenAccept(value -> {
            boolean alreadyVerified = false;
            if (value != null) {
                try {
                    alreadyVerified = Long.parseLong(value) > System.currentTimeMillis();
                    if (alreadyVerified) verified.add(id);
                } catch (NumberFormatException ignored) {}
            }
            if (alreadyVerified || !player.isOnline() || bypassCaptcha(player)) return;
            long window = Math.max(1, getConfig().getLong("antibot.join-window-seconds", 10)) * 1000L;
            int threshold = Math.max(1, getConfig().getInt("antibot.join-threshold", 6));
            long joins = joinTimes.values().stream().filter(t -> now - t <= window).count();
            int attackMultiplier = Math.max(1, getConfig().getInt("antibot.attack-mode-multiplier", 3));
            protectionLevel = joins >= threshold * attackMultiplier ? 3 : joins >= threshold * 2L ? 2 : joins >= threshold ? 1 : 0;
            if (joins >= threshold * attackMultiplier) {
                recordViolation(id, "join-flood-attack-mode");
                Bukkit.getScheduler().runTask(this, () -> player.kickPlayer(
                        getConfig().getString("messages.join-flood", "§cJoin flood protection is active.")));
                return;
            }
            if (joins >= threshold
                    || getConfig().getBoolean("antibot.always-check-new-players", false)
                    || (getConfig().getBoolean("new-account-protection.enabled", true) && isNewAccount(player))) {
                Bukkit.getScheduler().runTask(this, () -> activateChallenge(player));
            }
        }).exceptionally(error -> { getLogger().warning("Verification lookup failed: " + error.getMessage()); return null; });
    }

    private void activateChallenge(Player player) {
        UUID id = player.getUniqueId();
        if (!checking.add(id)) return;
        int correct = new SecureRandom().nextInt(9);
        captchaSlots.put(id, correct);
        captchaAttempts.put(id, 0);
        captchaStarted.put(id, System.currentTimeMillis());

        Bukkit.getScheduler().runTask(this, () -> {
            if (!player.isOnline()) { finishCheck(player, false); return; }
            if (SecurityClientAccess.isBedrock(player)) openBedrockCaptcha(player, correct);
            else openJavaCaptcha(player, correct);

            long timeout = Math.max(5L, getConfig().getLong("captcha.timeout-seconds", 20L)) * 20L;
            Bukkit.getScheduler().runTaskLater(this, () -> {
                if (checking.contains(id)) {
                    finishCheck(player, false);
                    if (player.isOnline()) player.kickPlayer(getConfig().getString("messages.timeout", "§cVerification timed out."));
                }
            }, timeout);
        });
    }

    private void openJavaCaptcha(Player player, int correct) {
        List<String> labels = List.of("Emerald", "Amethyst", "Copper", "Quartz", "Lapis", "Obsidian", "Prismarine", "Redstone", "Diamond");
        List<ActionButton> choices = new ArrayList<>();
        List<Integer> order = new ArrayList<>(List.of(0,1,2,3,4,5,6,7,8));
        Collections.shuffle(order);
        for (int option : order) {
            String label = labels.get(option);
            choices.add(securityButton(label, "Choose " + labels.get(correct) + ".", "/antibot verify " + option,
                    NamedTextColor.AQUA));
        }
        Dialog dialog = Dialog.create(builder -> builder.empty()
                .base(DialogBase.builder(Component.text("Security Verification", NamedTextColor.WHITE))
                        .externalTitle(Component.text("Verify", NamedTextColor.AQUA))
                        .canCloseWithEscape(false)
                        .body(List.of(
                                DialogBody.plainMessage(Component.text("Select the item named " + labels.get(correct) + ".", NamedTextColor.WHITE), 320),
                                DialogBody.plainMessage(Component.text("You have a limited time and limited attempts.", NamedTextColor.GRAY), 320)))
                        .build())
                .type(DialogType.multiAction(choices).columns(3).build()));
        player.showDialog(dialog);
    }

    private void openBedrockCaptcha(Player player, int correct) {
        if (!Bukkit.getPluginManager().isPluginEnabled("floodgate")) {
            player.kickPlayer("§cBedrock verification requires Floodgate. Please contact staff.");
            finishCheck(player, false);
            return;
        }
        List<String> labels = List.of("Emerald", "Amethyst", "Copper", "Quartz", "Lapis", "Obsidian", "Prismarine", "Redstone", "Diamond");
        List<Integer> options = new ArrayList<>(List.of(0,1,2,3,4,5,6,7,8));
        Collections.shuffle(options);
        SimpleForm.Builder form = SimpleForm.builder().title("Security Verification")
                .content("Select the item named " + labels.get(correct) + ".");
        List<Integer> actionChoices = new ArrayList<>();
        for (int option : options) {
            form.button(labels.get(option));
            actionChoices.add(option);
        }
        form.validResultHandler((SimpleFormResponse response) -> {
            int index = response.clickedButtonId();
            Bukkit.getScheduler().runTask(this, () -> {
                if (!player.isOnline() || !checking.contains(player.getUniqueId())) return;
                if (index < 0 || index >= actionChoices.size()) return;
                handleVerificationChoice(player, actionChoices.get(index));
            });
        });
        try {
            boolean sent = FloodgateApi.getInstance().sendForm(player.getUniqueId(), form.build());
            if (!sent) {
                finishCheck(player, false);
                player.kickPlayer("§cCould not open verification form. Please reconnect.");
            }
        } catch (LinkageError | RuntimeException error) {
            getLogger().warning("Could not open Bedrock verification form: " + error.getMessage());
            finishCheck(player, false);
            player.kickPlayer("§cCould not open verification form. Please reconnect.");
        }
    }

    public void handleVerificationChoice(Player player, int choice) {
        UUID id = player.getUniqueId();
        if (!player.isOnline() || !checking.contains(id)) return;
        Integer correct = captchaSlots.get(id);
        if (correct == null) return;

        int attempts = captchaAttempts.merge(id, 1, Integer::sum);
        int maxAttempts = Math.max(1, getConfig().getInt("captcha.max-attempts", 2));
        if (choice != correct) {
            if (attempts >= maxAttempts) {
                recordViolation(id, "captcha-failed").exceptionally(error -> {
                    getLogger().warning("Could not persist CAPTCHA failure for " + id + ": " + error.getMessage());
                    return null;
                });
                finishCheck(player, false);
                player.kickPlayer(getConfig().getString("messages.failed", "§cVerification failed."));
                return;
            }
            player.sendMessage(color(getConfig().getString("messages.retry", "&cIncorrect choice. Try again.")));
            if (SecurityClientAccess.isBedrock(player)) openBedrockCaptcha(player, correct);
            else openJavaCaptcha(player, correct);
            return;
        }

        finishCheck(player, true);
        player.sendMessage(color(getConfig().getString("messages.verified", "&aVerification successful.")));
    }

    @EventHandler
    public void onCaptchaClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && checking.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (event.getTo() == null) return;
        UUID id = event.getPlayer().getUniqueId();
        if (authRequired.contains(id)) {
            event.setTo(event.getFrom());
            return;
        }
        if (checking.contains(id)
                && (event.getFrom().getBlockX() != event.getTo().getBlockX()
                || event.getFrom().getBlockZ() != event.getTo().getBlockZ())) {
            event.setTo(event.getFrom());
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onDamage(EntityDamageEvent event) {
        if (!(event.getEntity() instanceof Player player)) return;
        UUID id = player.getUniqueId();
        if (authRequired.contains(id)) { event.setCancelled(true); return; }
        if (checking.contains(id)) { event.setCancelled(true); return; }
        if (!allowAction(id)) { event.setCancelled(true); recordViolation(id, "combat-rate-limit"); }
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!enabled) return;
        if (authRequired.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            return;
        }
        if (checking.contains(event.getPlayer().getUniqueId())) {
            String raw = event.getMessage().toLowerCase(Locale.ROOT);
            if (raw.startsWith("/antibot verify ")) return;
            event.setCancelled(true);
            return;
        }
        if (!allowAction(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            recordViolation(event.getPlayer().getUniqueId(), "command-rate-limit");
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        if (authRequired.contains(id) || checking.contains(id)) event.setCancelled(true);
    }

    @EventHandler
    public void onInventoryAction(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && (authRequired.contains(player.getUniqueId()) || checking.contains(player.getUniqueId()))) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        if (authRequired.contains(id) || checking.contains(id)) event.setCancelled(true);
    }

    @EventHandler
    public void onBlockPlace(BlockPlaceEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        if (authRequired.contains(id)) { event.setCancelled(true); return; }
        if (checking.contains(id)) { event.setCancelled(true); return; }
        if (!allowAction(id)) { event.setCancelled(true); recordViolation(id, "block-place-rate-limit"); }
    }

    @EventHandler
    public void onBlockBreak(BlockBreakEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        if (checking.contains(id)) { event.setCancelled(true); return; }
        if (!allowAction(id)) { event.setCancelled(true); recordViolation(id, "block-break-rate-limit"); }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        actionWindows.remove(id);
        rateLimitBypass.remove(id);
        authenticated.remove(id);
        authRequired.remove(id);
        authAttempts.remove(id);
        joinTimes.remove(id);
        riskScores.remove(id);
        blockedUntil.remove(id);
        checking.remove(id);
        captchaSlots.remove(id);
        captchaAttempts.remove(id);
        captchaStarted.remove(id);
        violationCooldowns.keySet().removeIf(key -> key.startsWith(id.toString() + "|"));
    }

    private boolean authEnabled() {
        return false;
    }

    private void prepareAuthWorld() {
        if (!getConfig().getBoolean("authentication.void-world.enabled", true)) return;
        String name = getConfig().getString("authentication.void-world.name", "VoidFlame-Auth");
        authWorld = Bukkit.getWorld(name);
        if (authWorld != null) return;
        WorldCreator creator = new WorldCreator(name);
        creator.generator(new ChunkGenerator() {
            @Override
            public ChunkData generateChunkData(World world, java.util.Random random, int chunkX, int chunkZ, BiomeGrid biome) {
                return createChunkData(world);
            }
        });
        authWorld = creator.createWorld();
        if (authWorld != null) {
            authWorld.setAutoSave(false);
            authWorld.setGameRule(org.bukkit.GameRule.DO_DAYLIGHT_CYCLE, false);
            authWorld.setGameRule(org.bukkit.GameRule.DO_WEATHER_CYCLE, false);
            authWorld.setTime(6000L);
            authWorld.setStorm(false);
        }
    }

    private void isolateForAuthentication(Player player) {
        if (authWorld == null) prepareAuthWorld();
        if (authWorld == null) return;
        org.bukkit.Location location = new org.bukkit.Location(authWorld, 0.5, 100.0, 0.5, 0f, 0f);
        player.setGameMode(org.bukkit.GameMode.ADVENTURE);
        player.setInvulnerable(true);
        player.teleportAsync(location);
    }

    private void releaseAuthentication(Player player) {
        player.setInvulnerable(false);
        String worldName = getConfig().getString("authentication.release-world", "world");
        World world = Bukkit.getWorld(worldName);
        if (world != null) player.teleportAsync(world.getSpawnLocation());
    }

    private void prepareAuthentication(Player player) {
        UUID id = player.getUniqueId();
        storage.database().query("SELECT password_hash FROM auth_accounts WHERE uuid=?", id.toString())
                .thenAccept(rows -> Bukkit.getScheduler().runTask(this, () -> {
                    if (!player.isOnline() || !authEnabled() || Bukkit.getOnlineMode()) return;
                    authAttempts.put(id, 0);
                    authRequired.add(id);
                    isolateForAuthentication(player);
                    boolean registered = !rows.isEmpty()
                            && rows.get(0).get("password_hash") != null
                            && !String.valueOf(rows.get(0).get("password_hash")).isBlank();
                    player.sendMessage(color(getConfig().getString(
                            registered ? "authentication.messages.login" : "authentication.messages.register",
                            registered ? "&5VoidFlame &7» &fLogin with &d/login <password>"
                                       : "&5VoidFlame &7» &fRegister with &d/register <password> <confirm>")));
                })).exceptionally(error -> {
                    getLogger().warning("Authentication lookup failed: " + error.getMessage());
                    return null;
                });
    }

    private boolean handleAuthenticationCommand(Player player, String raw) {
        if (!authEnabled() || Bukkit.getOnlineMode() || !authRequired.contains(player.getUniqueId())) return false;
        String[] parts = raw.trim().split("\\s+");
        if (parts.length == 0) return true;
        String command = parts[0].toLowerCase(Locale.ROOT);
        if (!command.equals("/register") && !command.equals("/login")) {
            player.sendMessage(color(getConfig().getString("authentication.messages.required", "&cYou must authenticate before playing.")));
            return true;
        }
        int maxAttempts = Math.max(1, getConfig().getInt("authentication.max-attempts", 5));
        int attempts = authAttempts.getOrDefault(player.getUniqueId(), 0);
        if (attempts >= maxAttempts) {
            player.kickPlayer(color(getConfig().getString("authentication.messages.too-many-attempts", "&cToo many authentication attempts.")));
            return true;
        }
        authAttempts.merge(player.getUniqueId(), 1, Integer::sum);
        if (command.equals("/register")) {
            if (parts.length != 3 || parts[1].length() < getConfig().getInt("authentication.password-min-length", 8)
                    || !parts[1].equals(parts[2])) {
                player.sendMessage(color(getConfig().getString("authentication.messages.register-usage", "&cUsage: /register <password> <confirm>")));
                return true;
            }
            String password = parts[1];
            if (!password.matches("[A-Za-z0-9!@#$%^&*()_+\\-=\\[\\]{};':\\\\\\\",.<>/?]+")) {
                player.sendMessage(color(getConfig().getString("authentication.messages.invalid-password", "&cPassword contains unsupported characters.")));
                return true;
            }
            storage.database().query("SELECT password_hash FROM auth_accounts WHERE uuid=?", player.getUniqueId().toString())
                    .thenCompose(rows -> {
                        if (!rows.isEmpty() && rows.get(0).get("password_hash") != null
                                && !String.valueOf(rows.get(0).get("password_hash")).isBlank()) {
                            player.sendMessage(color("&cThis account is already registered. Use /login <password>."));
                            return CompletableFuture.completedFuture(null);
                        }
                        String encoded = hashPassword(password);
                        long now = System.currentTimeMillis();
                        return storage.database().execute(
                                "INSERT INTO auth_accounts(uuid,password_hash,created_at,updated_at,failed_attempts,locked_until) VALUES(?,?,?, ?,0,0)",
                                player.getUniqueId().toString(), encoded, now, now);
                    }).thenRun(() -> Bukkit.getScheduler().runTask(this, () -> {
                        if (!player.isOnline()) return;
                        authenticated.add(player.getUniqueId());
                        authRequired.remove(player.getUniqueId());
                        authAttempts.remove(player.getUniqueId());
                        releaseAuthentication(player);
                        player.sendMessage(color(getConfig().getString("authentication.messages.registered", "&aRegistration successful.")));
                    })).exceptionally(error -> {
                        getLogger().warning("Authentication registration failed: " + error.getMessage());
                        return null;
                    });
            return true;
        }
        if (parts.length != 2) {
            player.sendMessage(color(getConfig().getString("authentication.messages.login-usage", "&cUsage: /login <password>")));
            return true;
        }
        storage.database().query("SELECT password_hash,failed_attempts,locked_until FROM auth_accounts WHERE uuid=?",
                player.getUniqueId().toString()).thenAccept(rows -> Bukkit.getScheduler().runTask(this, () -> {
            if (rows.isEmpty()) {
                player.sendMessage(color(getConfig().getString("authentication.messages.invalid", "&cInvalid password.")));
                return;
            }
            Map<String,Object> row = rows.get(0);
            long lockedUntil = row.get("locked_until") instanceof Number n ? n.longValue() : 0L;
            if (lockedUntil > System.currentTimeMillis()) {
                player.kickPlayer(color(getConfig().getString("authentication.messages.too-many-attempts", "&cToo many authentication attempts.")));
                return;
            }
            String record = String.valueOf(row.get("password_hash"));
            if (!verifyPassword(parts[1], record)) {
                long failed = row.get("failed_attempts") instanceof Number n ? n.longValue() : 0L;
                long maxFailures = Math.max(1L, getConfig().getLong("authentication.max-attempts", 5L));
                long nextFailures = failed + 1L;
                long lockSeconds = Math.max(1L, getConfig().getLong("authentication.lock-seconds", 300L));
                long newLockedUntil = nextFailures >= maxFailures ? System.currentTimeMillis() + lockSeconds * 1000L : 0L;
                storage.database().execute("UPDATE auth_accounts SET failed_attempts=?,locked_until=?,updated_at=? WHERE uuid=?",
                        nextFailures, newLockedUntil, System.currentTimeMillis(), player.getUniqueId().toString());
                if (newLockedUntil > 0L) {
                    player.kickPlayer(color(getConfig().getString("authentication.messages.too-many-attempts", "&cToo many authentication attempts. Please reconnect later.")));
                } else {
                    player.sendMessage(color(getConfig().getString("authentication.messages.invalid", "&cInvalid password.")));
                }
                return;
            }
            storage.database().execute("UPDATE auth_accounts SET failed_attempts=0,locked_until=0,updated_at=? WHERE uuid=?",
                    System.currentTimeMillis(), player.getUniqueId().toString());
            authenticated.add(player.getUniqueId());
            authRequired.remove(player.getUniqueId());
            authAttempts.remove(player.getUniqueId());
            releaseAuthentication(player);
            player.sendMessage(color(getConfig().getString("authentication.messages.logged-in", "&aLogin successful.")));
        })).exceptionally(error -> {
            getLogger().warning("Authentication login lookup failed: " + error.getMessage());
            return null;
        });
        return true;
    }

    private String hashPassword(String password) {
        try {
            int iterations = Math.max(120_000, getConfig().getInt("authentication.pbkdf2-iterations", 210_000));
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return iterations + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to hash authentication password.", e);
        }
    }

    private boolean verifyPassword(String password, String encoded) {
        try {
            String[] parts = encoded.split(":", -1);
            if (parts.length != 3) return false;
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expected = Base64.getDecoder().decode(parts[2]);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, expected.length * 8);
            byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return java.security.MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isProtectionEnabled() { return enabled; }

    public void setProtectionEnabled(boolean value) {
        enabled = value;
        getConfig().set("settings.enabled", value);
        saveConfig();
        if (!value) {
            checking.forEach(id -> { Player player = Bukkit.getPlayer(id); if (player != null) player.closeInventory(); });
            checking.clear();
            captchaSlots.clear();
            captchaAttempts.clear();
            captchaStarted.clear();
        }
    }

    public boolean isLockdown() { return lockdown; }

    public void setLockdown(boolean value) {
        lockdown = value;
        getConfig().set("settings.lockdown", value);
        saveConfig();
        if (value) {
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (!isSecurityTrusted(player.getUniqueId())) {
                    player.kickPlayer(color(getConfig().getString("messages.lockdown", "&cThe server is temporarily locked down by security protection.")));
                }
            }
        }
    }

    public int getProtectionLevel() { return protectionLevel; }
    public int getVerifyingCount() { return checking.size(); }
    public int getWhitelistSize() { return whitelist.size(); }
    public int getRiskCount() { return riskScores.size(); }
    public int getMaxActionsPerSecond() { return getConfig().getInt("settings.max-actions-per-second", 8); }
    public void setMaxActionsPerSecond(int value) { int v=Math.max(1,Math.min(100,value)); getConfig().set("settings.max-actions-per-second",v); saveConfig(); }
    public int getJoinThreshold() { return getConfig().getInt("antibot.join-threshold", 4); }
    public void setJoinThreshold(int value) { int v=Math.max(1,Math.min(100,value)); getConfig().set("antibot.join-threshold",v); saveConfig(); }
    public int getVerifyScore() { return getConfig().getInt("escalation.verify-score", 5); }
    public void setVerifyScore(int value) { int v=Math.max(1,Math.min(100,value)); getConfig().set("escalation.verify-score",v); saveConfig(); }
    public int getBlockScore() { return getConfig().getInt("escalation.block-score", 20); }
    public void setBlockScore(int value) { int v=Math.max(1,Math.min(200,value)); getConfig().set("escalation.block-score",v); saveConfig(); }


    private String color(String message) {
        return org.bukkit.ChatColor.translateAlternateColorCodes('&', message == null ? "" : message);
    }

    private final class AuthListener implements Listener {
        @EventHandler
        public void onCommandPreprocess(PlayerCommandPreprocessEvent event) {
            if (handleAuthenticationCommand(event.getPlayer(), event.getMessage())) event.setCancelled(true);
        }

        @EventHandler
        public void onJoinAuth(PlayerJoinEvent event) {
            if (!authEnabled() || Bukkit.getOnlineMode()) return;
            event.getPlayer().sendMessage(color(getConfig().getString("authentication.messages.notice", "&7Authentication is required on offline-mode servers.")));
        }
    }

    public boolean isSecurityTrusted(UUID id) {
        Player player = Bukkit.getPlayer(id);
        return player != null && ((!SecurityClientAccess.isBedrock(player) && (player.isOp()
                || player.hasPermission("voidflame.security.bypass")))
                || whitelisted(player)
                || verified.contains(id));
    }

    private boolean whitelisted(Player player) {
        return getConfig().getBoolean("whitelist.enabled", true) && whitelist.contains(player.getUniqueId());
    }

    private boolean bypassCaptcha(Player player) {
        return (!SecurityClientAccess.isBedrock(player) && (player.isOp() || player.hasPermission("voidflame.security.bypass")))
                || (whitelisted(player) && getConfig().getBoolean("whitelist.bypass-captcha", true));
    }

    private boolean bypassRateLimits(UUID id) {
        if (Bukkit.isPrimaryThread()) {
            Player player = Bukkit.getPlayer(id);
            if (player != null) return bypassRateLimits(player);
        }
        return rateLimitBypass.contains(id)
                || (getConfig().getBoolean("whitelist.enabled", true)
                && getConfig().getBoolean("whitelist.bypass-rate-limits", true)
                && whitelist.contains(id));
    }

    private boolean bypassRateLimits(Player player) {
        boolean bypass = (!SecurityClientAccess.isBedrock(player)
                && (player.isOp() || player.hasPermission("voidflame.security.bypass")))
                || (whitelisted(player) && getConfig().getBoolean("whitelist.bypass-rate-limits", true));
        UUID id = player.getUniqueId();
        if (bypass) rateLimitBypass.add(id);
        else rateLimitBypass.remove(id);
        return bypass;
    }

    private void loadWhitelistAsync() {
        storage.get("security", "whitelist").thenAccept(raw -> {
            if (raw == null || raw.isBlank()) return;
            for (String value : raw.split(",")) {
                try { whitelist.add(UUID.fromString(value)); } catch (IllegalArgumentException ignored) {}
            }
        }).exceptionally(error -> { getLogger().warning("Could not load security whitelist: " + error.getMessage()); return null; });
    }

    private void finishCheck(Player player, boolean success) {
        UUID id = player.getUniqueId();
        checking.remove(id);
        captchaSlots.remove(id);
        captchaAttempts.remove(id);
        captchaStarted.remove(id);
        if (success) {
            verified.add(id);
            storage.put("security", "verified:" + id, Long.toString(System.currentTimeMillis() + Math.max(1L, getConfig().getLong("captcha.verification-hours", 24L)) * 60L * 60L * 1000L)).exceptionally(error -> { getLogger().warning("Could not persist verification for " + id + ": " + error.getMessage()); return null; });
        }
    }

    private boolean isNewAccount(Player player) {
        if (whitelist.contains(player.getUniqueId()) && getConfig().getBoolean("whitelist.bypass-new-account-protection", true)) return false;
        if (!player.hasPlayedBefore()) return true;
        long firstPlayed = player.getFirstPlayed();
        long minAgeDays = Math.max(0L, getConfig().getLong("new-account-protection.min-account-age-days", 7L));
        return firstPlayed > 0 && System.currentTimeMillis() - firstPlayed < minAgeDays * 24L * 60L * 60L * 1000L;
    }

    public boolean allowAction(UUID player) {
        long now = System.currentTimeMillis();
        int configured = Math.max(1, getConfig().getInt("settings.max-actions-per-second", 12));
        if (bypassRateLimits(player)) return true;
        int max = protectionLevel >= 2 ? Math.max(1, configured / 2) : configured;
        Deque<Long> window = actionWindows.computeIfAbsent(player, ignored -> new ArrayDeque<>());
        synchronized (window) {
            while (!window.isEmpty() && now - window.peekFirst() >= 1000L) window.removeFirst();
            if (window.size() >= max) return false;
            window.addLast(now);
            return true;
        }
    }

    public CompletableFuture<Void> recordViolation(UUID player, String reason) {
        long now = System.currentTimeMillis();
        long cooldown = Math.max(0L, getConfig().getLong("settings.false-positive-cooldown-seconds", 30L)) * 1000L;
        String cooldownKey = player + "|" + reason;
        Long previous = violationCooldowns.put(cooldownKey, now);
        if (previous != null && cooldown > 0L && now - previous < cooldown) return CompletableFuture.completedFuture(null);
        int score = riskScores.merge(player, 1, Integer::sum);
        int verifyAt = Math.max(1, getConfig().getInt("escalation.verify-score", 5));
        int throttleAt = Math.max(verifyAt, getConfig().getInt("escalation.throttle-score", 10));
        int blockAt = Math.max(throttleAt, getConfig().getInt("escalation.block-score", 20));
        if (score >= blockAt) {
            blockedUntil.put(player, System.currentTimeMillis()
                    + Math.max(5, getConfig().getLong("escalation.block-seconds", 60)) * 1000L);
            protectionLevel = Math.max(protectionLevel, 3);
            Bukkit.getScheduler().runTask(this, () -> {
                Player online = Bukkit.getPlayer(player);
                if (online != null && online.isOnline()) {
                    online.kickPlayer(getConfig().getString("messages.escalated-kick", "§cSecurity protection triggered."));
                }
            });
        } else if (score >= throttleAt) {
            protectionLevel = Math.max(protectionLevel, 2);
        } else if (score >= verifyAt) {
            protectionLevel = Math.max(protectionLevel, 1);
            Bukkit.getScheduler().runTask(this, () -> {
                Player online = Bukkit.getPlayer(player);
                if (online != null && online.isOnline() && !checking.contains(player) && !bypassCaptcha(online)) {
                    activateChallenge(online);
                }
            });
        }
        String key = "violation:" + player + ":" + System.currentTimeMillis();
        CompletableFuture<Void> persisted = storage.put("security", key, reason + "|score=" + score + "|level=" + protectionLevel);
        if (auditLogs != null) {
            auditLogs.log(player.toString(), "SECURITY_VIOLATION", player.toString(),
                    "reason=" + reason + "|score=" + score + "|level=" + protectionLevel);
        }
        return persisted;
    }

    private void decayProtection() {
        if (protectionLevel > 0) protectionLevel--;
        long now = System.currentTimeMillis();
        blockedUntil.entrySet().removeIf(entry -> entry.getValue() <= now);
        riskScores.replaceAll((uuid, score) -> Math.max(0, score - 1));
    }

    private boolean command(org.bukkit.command.CommandSender sender, String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("verify")) {
            if (!(sender instanceof Player player) || args.length < 2 || !checking.contains(player.getUniqueId())) {
                sender.sendMessage("§cNo active verification session.");
                return true;
            }
            try { handleVerificationChoice(player, Integer.parseInt(args[1])); }
            catch (NumberFormatException ex) { player.kickPlayer("§cInvalid verification response."); }
            return true;
        }
        if (sender instanceof Player player && SecurityClientAccess.isBedrock(player)) {
            sender.sendMessage("§cJava staff only.");
            return true;
        }
        if (!sender.hasPermission("voidflame.security.manage")) { sender.sendMessage("§cNo permission."); return true; }
        if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
            sender.sendMessage("§8§m----------------");
            sender.sendMessage("§bVoidFlame AntiBot");
            sender.sendMessage("§7Status: " + (enabled ? "§aON" : "§cOFF"));
            sender.sendMessage("§7Verifying: §f" + checking.size());
            sender.sendMessage("§7Whitelist: §f" + whitelist.size());
            sender.sendMessage("§7Protection level: §f" + protectionLevel);
            sender.sendMessage("§8§m----------------");
            return true;
        }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "on" -> { setProtectionEnabled(true); sender.sendMessage("§aAntiBot enabled."); }
            case "off" -> { setProtectionEnabled(false); sender.sendMessage("§cAntiBot disabled."); }
            case "lockdown" -> { setLockdown(!lockdown); sender.sendMessage("§eLockdown " + (lockdown ? "enabled." : "disabled.")); }
            case "whitelist" -> { if (args.length == 1 && sender instanceof Player player) openWhitelistGui(player); else handleWhitelist(sender, args); }
            case "gui" -> { if (sender instanceof Player player) openSecurityGui(player); }
            default -> sender.sendMessage("§cUsage: /antibot <on|off|lockdown|status|whitelist add|remove <player>|gui>");
        }
        return true;
    }

    private void handleWhitelist(org.bukkit.command.CommandSender sender, String[] args) {
        if (args.length < 3) { sender.sendMessage("§cUsage: /antibot whitelist <add|remove> <player>"); return; }
        String name = args[2];
        Player player = Bukkit.getPlayerExact(name);
        if (player == null) { sender.sendMessage("§cPlayer must be online."); return; }
        UUID id = player.getUniqueId();
        if (args[1].equalsIgnoreCase("add")) whitelist.add(id);
        else if (args[1].equalsIgnoreCase("remove")) whitelist.remove(id);
        else { sender.sendMessage("§cUse add or remove."); return; }
        String value = String.join(",", whitelist.stream().map(UUID::toString).toList());
        storage.put("security", "whitelist", value).exceptionally(error -> { getLogger().warning("Could not persist whitelist: " + error.getMessage()); return null; });
        sender.sendMessage("§aWhitelist updated.");
    }

    private List<String> tabComplete(String[] args) {
        if (args.length == 1) return List.of("on", "off", "status", "whitelist", "gui");
        if (args.length == 2 && args[0].equalsIgnoreCase("whitelist")) return List.of("add", "remove");
        return List.of();
    }

    private void openSecurityGui(Player viewer) {
        if (SecurityClientAccess.isBedrock(viewer) || !viewer.hasPermission("voidflame.security.manage")) {
            viewer.sendMessage("§cJava staff only.");
            return;
        }
        List<ActionButton> actions = new ArrayList<>();
        actions.add(securityButton(enabled ? "Disable Protection" : "Enable Protection",
                "Current protection level: " + protectionLevel + " • Verifying: " + checking.size(),
                "/antibot " + (enabled ? "off" : "on"), enabled ? NamedTextColor.RED : NamedTextColor.GREEN));
        actions.add(securityButton("Whitelist", "Manage trusted online identities.", "/antibot whitelist", NamedTextColor.AQUA));
        actions.add(securityButton(lockdown ? "Lockdown: Enabled" : "Lockdown: Disabled",
                "Current emergency admission setting.", "/antibot lockdown", NamedTextColor.GOLD));
        actions.add(securityButton("Refresh Status", "Refresh current protection state.", "/antibot status", NamedTextColor.BLUE));
         
        Dialog dialog = Dialog.create(builder -> builder.empty()
                .base(DialogBase.builder(Component.text("VoidFlame Security", NamedTextColor.WHITE))
                        .externalTitle(Component.text("Security", NamedTextColor.AQUA)).canCloseWithEscape(true)
                        .body(List.of(
                                DialogBody.plainMessage(Component.text("SECURITY CONTROL CENTER", NamedTextColor.AQUA), 300),
                                DialogBody.plainMessage(Component.text("AntiBot: " + (enabled ? "ON" : "OFF")
                                        + " • Lockdown: " + (lockdown ? "ON" : "OFF"), enabled ? NamedTextColor.GREEN : NamedTextColor.RED), 300),
                                DialogBody.plainMessage(Component.text("Protection level: " + protectionLevel
                                        + " • Verifying: " + checking.size() + " • Whitelist: " + whitelist.size(), NamedTextColor.GRAY), 300)))
                        .build())
                .type(DialogType.multiAction(actions).columns(2).build()));
        viewer.showDialog(dialog);
    }

    private ActionButton securityButton(String label, String tooltip, String command, NamedTextColor color) {
        return ActionButton.create(Component.text(label, color), Component.text(tooltip, NamedTextColor.GRAY),
                180, DialogAction.commandTemplate(command));
    }

    private void openWhitelistGui(Player viewer) {
        if (SecurityClientAccess.isBedrock(viewer) || !viewer.hasPermission("voidflame.security.manage")) {
            viewer.sendMessage("§cJava staff only.");
            return;
        }
        List<ActionButton> actions = new ArrayList<>();
        List<Player> players = new ArrayList<>(Bukkit.getOnlinePlayers());
        players.sort(Comparator.comparing(Player::getName, String.CASE_INSENSITIVE_ORDER));
        for (Player target : players) {
            boolean active = whitelist.contains(target.getUniqueId());
            actions.add(securityButton((active ? "Remove: " : "Trust: ") + target.getName(),
                    active ? "Remove this identity from the whitelist." : "Add this identity to the whitelist.",
                    "/antibot whitelist " + (active ? "remove " : "add ") + target.getName(),
                    active ? NamedTextColor.RED : NamedTextColor.GREEN));
            if (actions.size() >= 78) break;
        }
        actions.add(securityButton("Back to Security", "Return to the Security control center.", "/antibot gui", NamedTextColor.GRAY));
        Dialog dialog = Dialog.create(builder -> builder.empty()
                .base(DialogBase.builder(Component.text("Security Whitelist", NamedTextColor.WHITE))
                        .externalTitle(Component.text("Security", NamedTextColor.AQUA)).canCloseWithEscape(true)
                        .body(List.of(
                                DialogBody.plainMessage(Component.text("TRUSTED IDENTITIES", NamedTextColor.AQUA), 300),
                                DialogBody.plainMessage(Component.text("Select a player to add or remove them. Current whitelist: " + whitelist.size(), NamedTextColor.GRAY), 300)))
                        .build())
                .type(DialogType.multiAction(actions).columns(2).build()));
        viewer.showDialog(dialog);
    }

    private void persistWhitelist() {
        String value = String.join(",", whitelist.stream().map(UUID::toString).sorted().toList());
        storage.put("security", "whitelist", value).exceptionally(error -> { getLogger().warning("Could not persist whitelist: " + error.getMessage()); return null; });
    }

}
