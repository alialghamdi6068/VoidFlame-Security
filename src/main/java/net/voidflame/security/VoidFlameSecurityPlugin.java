package net.voidflame.security;

import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.player.*;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.plugin.RegisteredServiceProvider;
import org.bukkit.plugin.java.JavaPlugin;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;

public final class VoidFlameSecurityPlugin extends JavaPlugin implements Listener {
    private static final long VERIFIED_MS = 24L * 60L * 60L * 1000L;

    private Object storage;
    private Method put;
    private Method get;
    private final ConcurrentHashMap<UUID, Deque<Long>> actionWindows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Long> joinTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Integer> captchaSlots = new ConcurrentHashMap<>();
    private final Set<UUID> checking = ConcurrentHashMap.newKeySet();
    private final Set<UUID> verified = ConcurrentHashMap.newKeySet();
    private final Set<UUID> whitelist = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<UUID, Integer> captchaAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, Long> captchaStarted = new ConcurrentHashMap<>();
    private volatile boolean enabled;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        enabled = getConfig().getBoolean("settings.enabled", true);
        if (!connectStorage()) {
            getLogger().severe("VoidFlame-Core storage service is unavailable.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        loadWhitelist();
        getServer().getPluginManager().registerEvents(this, this);
        Objects.requireNonNull(getCommand("antibot")).setExecutor((sender, command, label, args) -> command(sender, args));
        Objects.requireNonNull(getCommand("antibot")).setTabCompleter((sender, command, alias, args) -> tabComplete(args));
        getLogger().info("VoidFlame-Security enabled: AntiBot + rate protection.");
    }

    private boolean connectStorage() {
        try {
            Class<?> type = Class.forName("net.voidflame.core.storage.StorageService");
            RegisteredServiceProvider<?> registration = getServer().getServicesManager().getRegistration(type);
            if (registration == null) return false;
            storage = registration.getProvider();
            put = type.getMethod("put", String.class, String.class, String.class);
            get = type.getMethod("get", String.class, String.class);
            return true;
        } catch (ReflectiveOperationException ex) {
            getLogger().severe("Storage connection failed: " + ex.getMessage());
            return false;
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID id = player.getUniqueId();
        long now = System.currentTimeMillis();
        joinTimes.put(id, now);

        if (!enabled || bypass(player)) return;
        loadVerified(player);

        long window = Math.max(1, getConfig().getLong("antibot.join-window-seconds", 10)) * 1000L;
        int threshold = Math.max(1, getConfig().getInt("antibot.join-threshold", 6));
        long joins = joinTimes.values().stream().filter(t -> now - t <= window).count();

        if (joins >= threshold) {
            activateChallenge(player);
        } else if (getConfig().getBoolean("antibot.always-check-new-players", false)) {
            activateChallenge(player);
        }
    }

    private void activateChallenge(Player player) {
        if (!checking.add(player.getUniqueId())) return;
        int size = Math.max(9, Math.min(54, getConfig().getInt("captcha.size", 27)));
        int slots = size / 9;
        int correct = new Random().nextInt(size);
        captchaSlots.put(player.getUniqueId(), correct);
        captchaAttempts.put(player.getUniqueId(), 0);
        captchaStarted.put(player.getUniqueId(), System.currentTimeMillis());

        Bukkit.getScheduler().runTask(this, () -> {
            if (!player.isOnline()) { finishCheck(player, false); return; }
            Inventory inv = Bukkit.createInventory(null, slots * 9,
                    getConfig().getString("captcha.title", "§8Security Verification"));
            Material correctMaterial = material("captcha.correct-item", Material.EMERALD);
            Material filler = material("captcha.filler-item", Material.GRAY_STAINED_GLASS_PANE);
            ItemStack fillerStack = item(filler, getConfig().getString("captcha.filler-name", "§7Verification"));
            for (int i = 0; i < inv.getSize(); i++) inv.setItem(i, fillerStack.clone());
            inv.setItem(correct, item(correctMaterial, getConfig().getString("captcha.correct-name", "§aClick to verify")));
            player.openInventory(inv);

            long timeout = Math.max(5, getConfig().getLong("captcha.timeout-seconds", 20)) * 20L;
            Bukkit.getScheduler().runTaskLater(this, () -> {
                if (checking.contains(player.getUniqueId())) {
                    finishCheck(player, false);
                    if (player.isOnline()) player.kickPlayer(getConfig().getString("messages.timeout", "§cVerification timed out."));
                }
            }, timeout);
        });
    }

    @EventHandler
    public void onCaptchaClick(InventoryClickEvent event) {
        if (!(event.getWhoClicked() instanceof Player player) || !checking.contains(player.getUniqueId())) return;
        event.setCancelled(true);
        if (!event.getView().getTitle().equals(getConfig().getString("captcha.title", "§8Security Verification"))) return;

        Integer correct = captchaSlots.get(player.getUniqueId());
        int attempts = captchaAttempts.merge(player.getUniqueId(), 1, Integer::sum);
        int maxAttempts = Math.max(1, getConfig().getInt("captcha.max-attempts", 3));
        if (correct == null) return;
        if (attempts > maxAttempts) {
            finishCheck(player, false);
            player.closeInventory();
            player.kickPlayer(getConfig().getString("messages.failed", "§cVerification failed."));
            return;
        }
        if (event.getRawSlot() == correct) {
            finishCheck(player, true);
            player.closeInventory();
            player.sendMessage(getConfig().getString("messages.verified", "§aVerification successful."));
        } else if (event.getRawSlot() >= 0 && event.getRawSlot() < event.getInventory().getSize()) {
            finishCheck(player, false);
            player.closeInventory();
            player.kickPlayer(getConfig().getString("messages.failed", "§cVerification failed."));
        }
    }

    @EventHandler
    public void onClose(InventoryCloseEvent event) {
        if (event.getPlayer() instanceof Player player && checking.contains(player.getUniqueId())) {
            Bukkit.getScheduler().runTask(this, () -> {
                if (checking.contains(player.getUniqueId()) && player.isOnline()) player.openInventory(event.getInventory());
            });
        }
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (checking.contains(event.getPlayer().getUniqueId())
                && (event.getFrom().getBlockX() != event.getTo().getBlockX()
                || event.getFrom().getBlockZ() != event.getTo().getBlockZ())) {
            event.setTo(event.getFrom());
        }
    }

    @EventHandler
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player && checking.contains(player.getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (checking.contains(event.getPlayer().getUniqueId())) {
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
        if (checking.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            return;
        }
        if (!allowAction(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            recordViolation(event.getPlayer().getUniqueId(), "chat-rate-limit");
        }
    }

    @EventHandler
    public void onBlockPlace(BlockPlaceEvent event) {
        if (checking.contains(event.getPlayer().getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onBlockBreak(BlockBreakEvent event) {
        if (checking.contains(event.getPlayer().getUniqueId())) event.setCancelled(true);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        actionWindows.remove(id);
        joinTimes.remove(id);
        checking.remove(id);
        captchaSlots.remove(id);
        captchaAttempts.remove(id);
        captchaStarted.remove(id);
        captchaAttempts.remove(id);
        captchaStarted.remove(id);
        captchaAttempts.remove(id);
        captchaStarted.remove(id);
    }

    private boolean bypass(Player player) {
        return player.isOp() || player.hasPermission("voidflame.security.bypass") || whitelist.contains(player.getUniqueId());
    }

    private boolean isVerified(UUID id) {
        return verified.contains(id);
    }

    private void loadVerified(Player player) {
        UUID id = player.getUniqueId();
        if (verified.contains(id)) return;
        try {
            @SuppressWarnings("unchecked")
            CompletableFuture<String> future = (CompletableFuture<String>) get.invoke(storage, "security", "verified:" + id);
            future.thenAccept(value -> {
                if (value == null) return;
                try {
                    long expires = Long.parseLong(value);
                    if (expires > System.currentTimeMillis()) verified.add(id);
                    else put.invoke(storage, "security", "verified:" + id, "0");
                } catch (NumberFormatException ignored) {}
            });
        } catch (ReflectiveOperationException ignored) {}
    }

    private void finishCheck(Player player, boolean success) {
        UUID id = player.getUniqueId();
        checking.remove(id);
        captchaSlots.remove(id);
        if (success) {
            verified.add(id);
            try { put.invoke(storage, "security", "verified:" + id, Long.toString(System.currentTimeMillis() + VERIFIED_MS)); }
            catch (ReflectiveOperationException ex) { getLogger().warning("Could not persist verification for " + id); }
        }
    }

    private void loadWhitelist() {
        try {
            String raw = (String) get.invoke(storage, "security", "whitelist");
            if (raw != null && !raw.isBlank()) for (String value : raw.split(",")) {
                try { whitelist.add(UUID.fromString(value)); } catch (IllegalArgumentException ignored) {}
            }
        } catch (ReflectiveOperationException ignored) {}
    }

    public boolean allowAction(UUID player) {
        long now = System.currentTimeMillis();
        int max = Math.max(1, getConfig().getInt("settings.max-actions-per-second", 12));
        Deque<Long> window = actionWindows.computeIfAbsent(player, ignored -> new ArrayDeque<>());
        synchronized (window) {
            while (!window.isEmpty() && now - window.peekFirst() >= 1000L) window.removeFirst();
            if (window.size() >= max) return false;
            window.addLast(now);
            return true;
        }
    }

    public CompletableFuture<Void> recordViolation(UUID player, String reason) {
        try {
            String key = "violation:" + player + ":" + System.currentTimeMillis();
            return (CompletableFuture<Void>) put.invoke(storage, "security", key, reason);
        } catch (ReflectiveOperationException ex) {
            return CompletableFuture.failedFuture(ex);
        }
    }

    private boolean command(org.bukkit.command.CommandSender sender, String[] args) {
        if (!sender.hasPermission("voidflame.security.admin")) { sender.sendMessage("§cNo permission."); return true; }
        if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
            sender.sendMessage("§8§m----------------");
            sender.sendMessage("§bVoidFlame AntiBot");
            sender.sendMessage("§7Status: " + (enabled ? "§aON" : "§cOFF"));
            sender.sendMessage("§7Verifying: §f" + checking.size());
            sender.sendMessage("§7Whitelist: §f" + whitelist.size());
            sender.sendMessage("§8§m----------------");
            return true;
        }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "on" -> { enabled = true; getConfig().set("settings.enabled", true); saveConfig(); sender.sendMessage("§aAntiBot enabled."); }
            case "off" -> { enabled = false; getConfig().set("settings.enabled", false); saveConfig(); checking.forEach(id -> { Player p=Bukkit.getPlayer(id); if(p!=null) p.closeInventory(); }); checking.clear(); captchaSlots.clear(); sender.sendMessage("§cAntiBot disabled."); }
            case "whitelist" -> handleWhitelist(sender, args);
            default -> sender.sendMessage("§cUsage: /antibot <on|off|status|whitelist add|remove <player>>");
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
        try { put.invoke(storage, "security", "whitelist", value); }
        catch (ReflectiveOperationException ex) {
            sender.sendMessage("§cCould not persist whitelist.");
            return;
        }
        sender.sendMessage("§aWhitelist updated.");
    }

    private List<String> tabComplete(String[] args) {
        if (args.length == 1) return List.of("on", "off", "status", "whitelist");
        if (args.length == 2 && args[0].equalsIgnoreCase("whitelist")) return List.of("add", "remove");
        return List.of();
    }

    private Material material(String path, Material fallback) {
        Material m = Material.matchMaterial(getConfig().getString(path, fallback.name()));
        return m == null ? fallback : m;
    }

    private ItemStack item(Material material, String name) {
        ItemStack stack = new ItemStack(material);
        ItemMeta meta = stack.getItemMeta();
        if (meta != null) { meta.setDisplayName(name); stack.setItemMeta(meta); }
        return stack;
    }
}
