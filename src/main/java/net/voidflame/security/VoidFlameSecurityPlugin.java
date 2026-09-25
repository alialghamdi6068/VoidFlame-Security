package net.voidflame.security;

import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.plugin.RegisteredServiceProvider;
import org.bukkit.plugin.java.JavaPlugin;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public final class VoidFlameSecurityPlugin extends JavaPlugin implements Listener {
    private Object storage;
    private Method put;
    private final ConcurrentHashMap<UUID, Long> lastAction = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        if (!connectStorage()) {
            getLogger().severe("VoidFlame-Core storage service is unavailable.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        getServer().getPluginManager().registerEvents(this, this);
        getLogger().info("VoidFlame-Security enabled with persistent violation storage.");
    }

    private boolean connectStorage() {
        try {
            Class<?> type = Class.forName("net.voidflame.core.storage.StorageService");
            RegisteredServiceProvider<?> registration = getServer().getServicesManager().getRegistration(type);
            if (registration == null) return false;
            storage = registration.getProvider();
            put = type.getMethod("put", String.class, String.class, String.class);
            return true;
        } catch (ReflectiveOperationException ex) {
            return false;
        }
    }

    public boolean allowAction(UUID player) {
        long now = System.currentTimeMillis();
        long minimum = 1000L / Math.max(1, getConfig().getInt("settings.max-actions-per-second", 12));
        Long previous = lastAction.put(player, now);
        return previous == null || now - previous >= minimum;
    }

    public CompletableFuture<Void> recordViolation(UUID player, String reason) {
        try {
            return (CompletableFuture<Void>) put.invoke(storage, "security", "violation:" + player, reason + ":" + System.currentTimeMillis());
        } catch (ReflectiveOperationException ex) {
            return CompletableFuture.failedFuture(ex);
        }
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!allowAction(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            recordViolation(event.getPlayer().getUniqueId(), "command-rate-limit");
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        if (!allowAction(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            recordViolation(event.getPlayer().getUniqueId(), "chat-rate-limit");
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        lastAction.remove(event.getPlayer().getUniqueId());
    }
}
