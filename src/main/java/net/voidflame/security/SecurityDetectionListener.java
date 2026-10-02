package net.voidflame.security;

import org.bukkit.GameMode;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.event.player.PlayerVelocityEvent;
import org.bukkit.util.Vector;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class SecurityDetectionListener implements Listener {
    private final VoidFlameSecurityPlugin plugin;
    private final Map<UUID, Long> lastMoveViolation = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> moveViolations = new ConcurrentHashMap<>();
    private final Map<UUID, Long> lastAttack = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> attackBursts = new ConcurrentHashMap<>();
    private final Map<UUID, Long> graceUntil = new ConcurrentHashMap<>();

    public SecurityDetectionListener(VoidFlameSecurityPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onVelocity(PlayerVelocityEvent event) {
        long grace = Math.max(100L, plugin.getConfig().getLong("anti-cheat.movement.velocity-grace-ms", 750L));
        graceUntil.put(event.getPlayer().getUniqueId(), System.currentTimeMillis() + grace);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onTeleport(PlayerTeleportEvent event) {
        long grace = Math.max(100L, plugin.getConfig().getLong("anti-cheat.movement.teleport-grace-ms", 1500L));
        graceUntil.put(event.getPlayer().getUniqueId(), System.currentTimeMillis() + grace);
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        if (!plugin.getConfig().getBoolean("anti-cheat.enabled", true)
                || !plugin.getConfig().getBoolean("anti-cheat.movement.enabled", true)
                || event.getTo() == null) return;

        Player player = event.getPlayer();
        if (player.isOp() || player.hasPermission("voidflame.security.anticheat.bypass")) return;
        if (player.getGameMode() == GameMode.SPECTATOR
                || player.getGameMode() == GameMode.CREATIVE
                || player.isFlying()
                || player.isGliding()
                || player.isInsideVehicle()) return;

        long now = System.currentTimeMillis();
        if (graceUntil.getOrDefault(player.getUniqueId(), 0L) > now) return;

        double dx = event.getTo().getX() - event.getFrom().getX();
        double dz = event.getTo().getZ() - event.getFrom().getZ();
        double horizontal = Math.sqrt(dx * dx + dz * dz);
        double vertical = Math.abs(event.getTo().getY() - event.getFrom().getY());

        double maxHorizontal = Math.max(0.5D,
                plugin.getConfig().getDouble("anti-cheat.movement.max-horizontal-per-event", 1.25D));
        double maxVertical = Math.max(0.75D,
                plugin.getConfig().getDouble("anti-cheat.movement.max-vertical-per-event", 2.25D));

        boolean suspicious = horizontal > maxHorizontal || vertical > maxVertical;
        if (!suspicious) {
            moveViolations.compute(player.getUniqueId(), (id, value) ->
                    value == null ? 0 : Math.max(0, value - 1));
            return;
        }

        UUID id = player.getUniqueId();
        long previous = lastMoveViolation.getOrDefault(id, 0L);
        if (now - previous < 250L) return;
        lastMoveViolation.put(id, now);

        int streak = moveViolations.merge(id, 1, Integer::sum);
        int threshold = Math.max(2,
                plugin.getConfig().getInt("anti-cheat.movement.flag-after", 4));

        if (streak >= threshold) {
            moveViolations.put(id, 0);
            plugin.recordViolation(id, "movement-anomaly");
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onAttack(EntityDamageByEntityEvent event) {
        if (!plugin.getConfig().getBoolean("anti-cheat.enabled", true)
                || !plugin.getConfig().getBoolean("anti-cheat.combat.enabled", true)) return;
        if (!(event.getDamager() instanceof Player attacker) || !(event.getEntity() instanceof Player target)) return;
        if (attacker.isOp() || attacker.hasPermission("voidflame.security.anticheat.bypass")) return;
        if (attacker.getGameMode() == GameMode.SPECTATOR) return;

        double maxReach = Math.max(3.25D,
                plugin.getConfig().getDouble("anti-cheat.combat.max-reach", 4.25D));
        double distance = attacker.getEyeLocation().distance(target.getBoundingBox().getCenter().toLocation(target.getWorld()));
        if (distance > maxReach) {
            plugin.recordViolation(attacker.getUniqueId(), "combat-reach-anomaly");
            return;
        }

        long now = System.currentTimeMillis();
        UUID id = attacker.getUniqueId();
        long previous = lastAttack.getOrDefault(id, 0L);
        lastAttack.put(id, now);
        if (previous <= 0L) return;

        long delta = now - previous;
        long minimum = Math.max(25L,
                plugin.getConfig().getLong("anti-cheat.combat.min-attack-interval-ms", 45L));
        if (delta >= minimum) {
            attackBursts.compute(id, (key, value) -> value == null ? 0 : Math.max(0, value - 1));
            return;
        }

        int burst = attackBursts.merge(id, 1, Integer::sum);
        int threshold = Math.max(3,
                plugin.getConfig().getInt("anti-cheat.combat.flag-after-fast-attacks", 8));
        if (burst >= threshold) {
            attackBursts.put(id, 0);
            plugin.recordViolation(id, "combat-click-rate-anomaly");
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        lastMoveViolation.remove(id);
        moveViolations.remove(id);
        lastAttack.remove(id);
        attackBursts.remove(id);
        graceUntil.remove(id);
    }
}
