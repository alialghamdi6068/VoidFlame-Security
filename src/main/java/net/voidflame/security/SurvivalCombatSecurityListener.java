package net.voidflame.security;

import net.kyori.adventure.text.Component;
import org.bukkit.ChatColor;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.inventory.ItemStack;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SurvivalCombatSecurityListener implements Listener {
    private final JavaPlugin plugin;
    private final Map<UUID, Long> taggedUntil = new ConcurrentHashMap<>();

    public SurvivalCombatSecurityListener(JavaPlugin plugin) { this.plugin = plugin; }

    @EventHandler
    public void onPlayerDamage(EntityDamageByEntityEvent event) {
        if (!plugin.getConfig().getBoolean("combat-tag.enabled", true)) return;
        if (!(event.getEntity() instanceof Player victim)) return;
        Player attacker = null;
        if (event.getDamager() instanceof Player player) attacker = player;
        else if (event.getDamager() instanceof Projectile projectile && projectile.getShooter() instanceof Player player) attacker = player;
        if (attacker == null || attacker.getUniqueId().equals(victim.getUniqueId())) return;
        long seconds = Math.max(1L, plugin.getConfig().getLong("combat-tag.seconds", 15L));
        long until = System.currentTimeMillis() + seconds * 1000L;
        taggedUntil.put(victim.getUniqueId(), until);
        taggedUntil.put(attacker.getUniqueId(), until);
        victim.sendActionBar(Component.text(ChatColor.RED + "Combat tagged: " + ChatColor.WHITE + seconds + "s"));
        attacker.sendActionBar(Component.text(ChatColor.RED + "Combat tagged: " + ChatColor.WHITE + seconds + "s"));
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) { taggedUntil.remove(event.getPlayer().getUniqueId()); }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        long until = taggedUntil.getOrDefault(player.getUniqueId(), 0L);
        taggedUntil.remove(player.getUniqueId());
        if (!plugin.getConfig().getBoolean("combat-tag.enabled", true)
                || !plugin.getConfig().getBoolean("combat-tag.drop-inventory-on-logout", true)
                || until <= System.currentTimeMillis()
                || player.hasPermission("voidflame.security.combat.bypass")) return;

        for (ItemStack item : player.getInventory().getStorageContents()) drop(player, item);
        for (ItemStack item : player.getInventory().getArmorContents()) drop(player, item);
        drop(player, player.getInventory().getItemInOffHand());
        player.getInventory().clear();
        player.getInventory().setArmorContents(new ItemStack[4]);
        player.getInventory().setItemInOffHand(new ItemStack(Material.AIR));
        plugin.getLogger().info("Combat logout: dropped full inventory for " + player.getName() + " (" + player.getUniqueId() + ").");
    }

    private void drop(Player player, ItemStack item) {
        if (item == null || item.getType() == Material.AIR) return;
        player.getWorld().dropItemNaturally(player.getLocation(), item.clone());
    }
}
