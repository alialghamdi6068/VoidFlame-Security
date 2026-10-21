package net.voidflame.security;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

import java.lang.reflect.Method;
import java.util.UUID;

final class SecurityClientAccess {
    private SecurityClientAccess() {}

    static boolean isBedrock(Player player) {
        Plugin floodgate = Bukkit.getPluginManager().getPlugin("floodgate");
        if (floodgate != null && floodgate.isEnabled()) {
            try {
                Class<?> api = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
                Object instance = api.getMethod("getInstance").invoke(null);
                return Boolean.TRUE.equals(api.getMethod("isFloodgatePlayer", UUID.class).invoke(instance, player.getUniqueId()));
            } catch (ReflectiveOperationException | LinkageError ex) {
                return true;
            }
        }
        Plugin geyser = Bukkit.getPluginManager().getPlugin("Geyser-Spigot");
        if (geyser == null) geyser = Bukkit.getPluginManager().getPlugin("Geyser");
        if (geyser != null && geyser.isEnabled()) {
            try {
                Class<?> api = Class.forName("org.geysermc.geyser.api.GeyserApi");
                Object instance = api.getMethod("api").invoke(null);
                return Boolean.TRUE.equals(api.getMethod("isBedrockPlayer", UUID.class).invoke(instance, player.getUniqueId()));
            } catch (ReflectiveOperationException | LinkageError ex) {
                return true;
            }
        }
        return false;
    }

    static boolean hasJavaStaffIdentity(Player player) {
        return !isBedrock(player);
    }
}
