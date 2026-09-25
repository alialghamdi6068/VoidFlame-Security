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
import java.util.ArrayDeque;
import java.util.Deque;

public final class VoidFlameSecurityPlugin extends JavaPlugin implements Listener {
    private Object storage;
    private Method put;
    private final ConcurrentHashMap<UUID, Deque<Long>> actionWindows = new ConcurrentHashMap<>();

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
        actionWindows.remove(event.getPlayer().getUniqueId());
    }
}
