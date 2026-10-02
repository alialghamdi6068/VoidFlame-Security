package net.voidflame.security;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PluginMessageReceivedEvent;

import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public final class AdvancedProtectionListener implements Listener {
    private enum Mode { NORMAL, ELEVATED, HIGH, CRITICAL, LOCKDOWN }

    private static final class Window {
        final Deque<Long> times = new ArrayDeque<>();
        synchronized int addAndCount(long now, long windowMs) {
            while (!times.isEmpty() && now - times.peekFirst() > windowMs) times.removeFirst();
            times.addLast(now);
            return times.size();
        }
        synchronized int count(long now, long windowMs) {
            while (!times.isEmpty() && now - times.peekFirst() > windowMs) times.removeFirst();
            return times.size();
        }
    }

    private final VoidFlameSecurityPlugin plugin;
    private final Map<String, Window> ipJoins = new ConcurrentHashMap<>();
    private final Map<String, Window> subnetJoins = new ConcurrentHashMap<>();
    private final Map<String, Window> ipConnections = new ConcurrentHashMap<>();
    private final Map<UUID, Window> playerBursts = new ConcurrentHashMap<>();
    private final Map<String, Long> blockedIps = new ConcurrentHashMap<>();
    private final Map<String, Long> blockedSubnets = new ConcurrentHashMap<>();
    private final Map<UUID, Long> trustedUntil = new ConcurrentHashMap<>();
    private final AtomicLong attackStarted = new AtomicLong();
    private volatile Mode mode = Mode.NORMAL;
    private volatile long lastAlert = 0L;
    private volatile double lastTps = 20.0D;

    public AdvancedProtectionListener(VoidFlameSecurityPlugin plugin) {
        this.plugin = plugin;
        Bukkit.getScheduler().runTaskTimer(plugin, this::recalculateMode, 20L, 20L);
        Bukkit.getScheduler().runTaskTimer(plugin, this::cleanup, 20L * 30L, 20L * 30L);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!enabled()) return;

        final String ip = address(event.getAddress());
        final String subnet = subnet(ip);
        final long now = System.currentTimeMillis();

        if (isBlocked(ip, subnet, now)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message("messages.temporarily-blocked", "Security protection is active. Please try again later."));
            return;
        }

        int connectionCount = window(ipConnections, ip).addAndCount(now, millis("connection.window-seconds", 10));
        int joinCount = window(ipJoins, ip).count(now, millis("antibot.join-window-seconds", 10));
        int subnetCount = window(subnetJoins, subnet).count(now, millis("correlation.subnet-window-seconds", 10));

        int connectionLimit = scaledLimit("connection.max-per-ip", 12);
        int burstLimit = scaledLimit("connection.max-burst-per-ip", 6);

        if (connectionCount > connectionLimit || joinCount >= burstLimit || subnetCount > scaledLimit("correlation.max-joins-per-subnet", 20)) {
            int score = 2;
            if (connectionCount > connectionLimit * 2 || subnetCount > scaledLimit("correlation.critical-subnet-joins", 40)) score = 4;
            plugin.recordViolation(event.getUniqueId(), "connection-flood:" + score);
            if (mode.ordinal() >= Mode.HIGH.ordinal() || connectionCount > connectionLimit * 2) {
                long blockSeconds = Math.max(5L, plugin.getConfig().getLong("blocking.ip-block-seconds", 60L));
                blockedIps.put(ip, now + blockSeconds * 1000L);
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message("messages.join-flood", "Join flood protection is active."));
                alert("Connection flood from " + ip + " (" + connectionCount + " connections, subnet=" + subnetCount + ")");
            }
        }

        if (mode == Mode.LOCKDOWN && !plugin.isSecurityTrusted(event.getUniqueId())) {
            int online = Bukkit.getOnlinePlayers().size();
            int reserved = Math.max(0, plugin.getConfig().getInt("lockdown.reserved-trusted-slots", 5));
            int maxPlayers = Bukkit.getMaxPlayers();
            if (online >= Math.max(1, maxPlayers - reserved)) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message("messages.lockdown", "The server is under temporary security lockdown."));
            }
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onLogin(PlayerLoginEvent event) {
        if (!enabled()) return;
        String ip = address(event.getAddress());
        String subnet = subnet(ip);
        long now = System.currentTimeMillis();
        if (isBlocked(ip, subnet, now) && !isTrusted(event.getPlayer())) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, message("messages.temporarily-blocked", "Security protection is active. Please try again later."));
            return;
        }

        if (mode == Mode.LOCKDOWN && !plugin.isSecurityTrusted(event.getPlayer().getUniqueId())) {
            int reserved = Math.max(0, plugin.getConfig().getInt("lockdown.reserved-trusted-slots", 5));
            if (Bukkit.getOnlinePlayers().size() >= Math.max(1, Bukkit.getMaxPlayers() - reserved)) {
                event.disallow(PlayerLoginEvent.Result.KICK_OTHER, message("messages.lockdown", "The server is under temporary security lockdown."));
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        if (!enabled()) return;
        Player player = event.getPlayer();
        String ip = address(player.getAddress() == null ? null : player.getAddress().getAddress());
        String subnet = subnet(ip);
        long now = System.currentTimeMillis();
        window(ipJoins, ip).addAndCount(now, millis("antibot.join-window-seconds", 10));
        window(subnetJoins, subnet).addAndCount(now, millis("correlation.subnet-window-seconds", 10));

        if (mode.ordinal() >= Mode.ELEVATED.ordinal() && !isTrusted(player)) {
            trustedUntil.put(player.getUniqueId(), now + millis("verified-cache.temporary-trust-seconds", 120));
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!enabled() || trusted(event.getPlayer())) return;
        if (!allowBurst(event.getPlayer(), "command", "commands.max-per-second", 6)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onChat(AsyncPlayerChatEvent event) {
        if (!enabled() || trusted(event.getPlayer())) return;
        if (!allowBurst(event.getPlayer(), "chat", "chat.max-per-second", 5)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (!enabled() || trusted(event.getPlayer())) return;
        if (!allowBurst(event.getPlayer(), "interact", "actions.max-interact-per-second", 18)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInventory(InventoryClickEvent event) {
        if (!(event.getWhoClicked() instanceof Player player) || !enabled() || trusted(player)) return;
        if (!allowBurst(player, "inventory", "actions.max-inventory-per-second", 18)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPluginMessage(PluginMessageReceivedEvent event) {
        if (!enabled() || !(event.getPlayer() instanceof Player player) || trusted(player)) return;
        byte[] data = event.getData();
        int maxBytes = scaledLimit("packets.max-plugin-message-bytes", 32767);
        if (data != null && data.length > maxBytes) {
            event.setCancelled(true);
            plugin.recordViolation(player.getUniqueId(), "oversized-plugin-payload:" + data.length);
        }
        if (!allowBurst(player, "payload", "packets.max-payloads-per-second", 30)) event.setCancelled(true);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        playerBursts.remove(event.getPlayer().getUniqueId());
        trustedUntil.remove(event.getPlayer().getUniqueId());
    }

    private boolean allowBurst(Player player, String type, String path, int fallback) {
        Window w = playerBursts.computeIfAbsent(player.getUniqueId(), ignored -> new Window());
        int limit = scaledLimit(path, fallback);
        int count = w.addAndCount(System.currentTimeMillis(), 1000L);
        if (count <= limit) return true;
        plugin.recordViolation(player.getUniqueId(), "burst-" + type);
        return false;
    }

    private void recalculateMode() {
        if (!enabled()) { mode = Mode.NORMAL; return; }

        double tps = 20.0D;
        try {
            double[] values = Bukkit.getTPS();
            if (values.length > 0 && values[0] > 0) tps = Math.min(20.0D, values[0]);
        } catch (Throwable ignored) {}
        lastTps = tps;

        long now = System.currentTimeMillis();
        int joins = totalRecent(ipJoins, now, millis("antibot.join-window-seconds", 10));
        int connections = totalRecent(ipConnections, now, millis("connection.window-seconds", 10));
        int subnets = activeCorrelatedSubnets(now);

        int elevated = Math.max(1, plugin.getConfig().getInt("attack-mode.elevated-joins", 4));
        int high = Math.max(elevated, plugin.getConfig().getInt("attack-mode.high-joins", 10));
        int critical = Math.max(high, plugin.getConfig().getInt("attack-mode.critical-joins", 20));
        int lockdown = Math.max(critical, plugin.getConfig().getInt("attack-mode.lockdown-joins", 35));

        Mode next = joins >= lockdown || connections >= lockdown * 2 ? Mode.LOCKDOWN
                : joins >= critical || connections >= critical * 2 ? Mode.CRITICAL
                : joins >= high || connections >= high * 2 ? Mode.HIGH
                : joins >= elevated || connections >= elevated * 2 ? Mode.ELEVATED
                : Mode.NORMAL;

        double tpsCritical = plugin.getConfig().getDouble("attack-mode.tps-critical", 14.0D);
        double tpsHigh = plugin.getConfig().getDouble("attack-mode.tps-high", 16.0D);
        if (tps <= tpsCritical && next.ordinal() < Mode.CRITICAL.ordinal()) next = Mode.CRITICAL;
        else if (tps <= tpsHigh && next.ordinal() < Mode.HIGH) next = Mode.HIGH;

        if (subnets >= plugin.getConfig().getInt("correlation.critical-active-subnets", 3)
                && next.ordinal() < Mode.CRITICAL.ordinal()) next = Mode.CRITICAL;

        if (next != mode) {
            Mode previous = mode;
            mode = next;
            if (next != Mode.NORMAL && attackStarted.compareAndSet(0L, now)) {
                alert("Attack mode entered: " + next + " (joins=" + joins + ", connections=" + connections + ", TPS=" + round(tps) + ")");
            } else if (next == Mode.NORMAL) {
                attackStarted.set(0L);
                alert("Attack mode cleared. TPS=" + round(tps));
            } else if (next.ordinal() > previous.ordinal()) {
                alert("Attack mode escalated: " + previous + " -> " + next + " (joins=" + joins + ", connections=" + connections + ")");
            }
        }
    }

    private boolean isBlocked(String ip, String subnet, long now) {
        Long ipUntil = blockedIps.get(ip);
        Long subnetUntil = blockedSubnets.get(subnet);
        return (ipUntil != null && ipUntil > now) || (subnetUntil != null && subnetUntil > now);
    }

    private boolean trusted(Player player) {
        if (isTrusted(player)) return true;
        Long until = trustedUntil.get(player.getUniqueId());
        return until != null && until > System.currentTimeMillis();
    }

    private boolean isTrusted(Player player) {
        return player.isOp() || player.hasPermission("voidflame.security.bypass");
    }

    private boolean isTrustedUuid(UUID id) {
        Player player = Bukkit.getPlayer(id);
        return player != null && isTrusted(player);
    }

    private int scaledLimit(String path, int fallback) {
        int base = Math.max(1, plugin.getConfig().getInt(path, fallback));
        return switch (mode) {
            case NORMAL -> base;
            case ELEVATED -> Math.max(1, (int) Math.ceil(base * 0.80D));
            case HIGH -> Math.max(1, (int) Math.ceil(base * 0.55D));
            case CRITICAL -> Math.max(1, (int) Math.ceil(base * 0.35D));
            case LOCKDOWN -> Math.max(1, (int) Math.ceil(base * 0.20D));
        };
    }

    private Window window(Map<String, Window> map, String key) {
        return map.computeIfAbsent(key, ignored -> new Window());
    }

    private int totalRecent(Map<String, Window> map, long now, long windowMs) {
        int total = 0;
        for (Window w : map.values()) total += w.count(now, windowMs);
        return total;
    }

    private int activeCorrelatedSubnets(long now) {
        int count = 0;
        long window = millis("correlation.subnet-window-seconds", 10);
        int threshold = Math.max(1, plugin.getConfig().getInt("correlation.active-subnet-threshold", 4));
        for (Window w : subnetJoins.values()) if (w.count(now, window) >= threshold) count++;
        return count;
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        blockedIps.entrySet().removeIf(e -> e.getValue() <= now);
        blockedSubnets.entrySet().removeIf(e -> e.getValue() <= now);
        ipJoins.entrySet().removeIf(e -> e.getValue().count(now, millis("antibot.join-window-seconds", 10)) == 0);
        subnetJoins.entrySet().removeIf(e -> e.getValue().count(now, millis("correlation.subnet-window-seconds", 10)) == 0);
        ipConnections.entrySet().removeIf(e -> e.getValue().count(now, millis("connection.window-seconds", 10)) == 0);
        trustedUntil.entrySet().removeIf(e -> e.getValue() <= now);
    }

    private long millis(String path, long fallbackSeconds) {
        return Math.max(1L, plugin.getConfig().getLong(path, fallbackSeconds)) * 1000L;
    }

    private boolean enabled() {
        return plugin.getConfig().getBoolean("settings.enabled", true);
    }

    private String address(InetAddress address) {
        return address == null ? "unknown" : address.getHostAddress();
    }

    private String subnet(String ip) {
        if (ip == null || ip.isBlank() || ip.equals("unknown")) return "unknown";
        if (ip.contains(":")) {
            String[] p = ip.split(":");
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < Math.min(4, p.length); i++) {
                if (i > 0) out.append(':');
                out.append(p[i]);
            }
            return out + "::/64";
        }
        int first = ip.indexOf('.');
        int second = ip.indexOf('.', first + 1);
        int third = ip.indexOf('.', second + 1);
        if (third < 0) return ip + "/32";
        return ip.substring(0, third) + ".0/24";
    }

    private String message(String path, String fallback) {
        return plugin.getConfig().getString(path, fallback);
    }

    private void alert(String text) {
        if (!plugin.getConfig().getBoolean("alerts.enabled", true)) return;
        long now = System.currentTimeMillis();
        long cooldown = Math.max(1L, plugin.getConfig().getLong("alerts.cooldown-seconds", 15L)) * 1000L;
        if (now - lastAlert < cooldown) return;
        lastAlert = now;

        String prefix = plugin.getConfig().getString("alerts.message-prefix", "§5[Security] §f");
        Bukkit.getOnlinePlayers().stream()
                .filter(this::isTrusted)
                .forEach(p -> p.sendMessage(prefix + text));

        String webhook = plugin.getConfig().getString("alerts.discord-webhook", "").trim();
        if (webhook.isEmpty()) return;
        if (!webhook.startsWith("https://discord.com/api/webhooks/")
                && !webhook.startsWith("https://discordapp.com/api/webhooks/")) return;

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> sendWebhook(webhook, text));
    }

    private void sendWebhook(String webhook, String text) {
        try {
            var client = java.net.http.HttpClient.newHttpClient();
            String body = "{\"content\":\""
                    + jsonEscape(text)
                    + "\"}";
            var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(webhook))
                    .header("Content-Type", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                    .build();
            client.send(request, java.net.http.HttpResponse.BodyHandlers.discarding());
        } catch (Exception ex) {
            plugin.getLogger().fine("Discord security alert failed: " + ex.getMessage());
        }
    }

    private String jsonEscape(String value) {
        return value.replace("\\\\", "\\\\\\\\").replace("\"", "\\\"")
                .replace("\\n", " ").replace("\\r", " ");
    }

    private String round(double value) {
        return String.format(java.util.Locale.ROOT, "%.2f", value);
    }
}
