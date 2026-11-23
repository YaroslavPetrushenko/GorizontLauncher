package com.gorizont.authplugin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Brute-force protection with escalating lockouts, keyed by IP address and never by nickname.
 *
 * Keying by nickname would let anybody lock the real owner of an account out by typing wrong passwords
 * for that nickname, and clearing the counter when a player disconnects would give a fresh set of
 * attempts on every reconnect. Here a failure belongs to the address it came from, survives
 * reconnects, expires only after a quiet period, and every lockout is longer than the previous one.
 * One guard is shared by the in-game /login and the launcher API, so the two doors count together.
 */
public final class BruteForceGuard {

    private static final long FAIL_WINDOW_MILLIS = 15 * 60_000L;   // failures older than this are forgotten
    private static final long STRIKE_MEMORY_MILLIS = 24 * 60 * 60_000L;

    private static final class State {
        int fails;
        int strikes;
        long lockedUntil;
        long touched;
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final long baseLockMillis;
    private final long maxLockMillis;

    public BruteForceGuard(int maxAttempts, long baseLockMinutes, long maxLockMinutes) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.baseLockMillis = Math.max(1, baseLockMinutes) * 60_000L;
        this.maxLockMillis = Math.max(baseLockMinutes, maxLockMinutes) * 60_000L;
    }

    /** Milliseconds left on the lockout of this address, 0 if it may try. */
    public long lockRemainingMillis(String ip) {
        State state = states.get(ip);
        if (state == null) return 0;
        long left = state.lockedUntil - System.currentTimeMillis();
        return Math.max(0, left);
    }

    public int attemptsLeft(String ip) {
        State state = states.get(ip);
        if (state == null) return maxAttempts;
        if (System.currentTimeMillis() - state.touched > FAIL_WINDOW_MILLIS) return maxAttempts;
        return Math.max(0, maxAttempts - state.fails);
    }

    /** Records a wrong password. Returns true if the address is locked out after this failure. */
    public synchronized boolean recordFailure(String ip) {
        long now = System.currentTimeMillis();
        State state = states.computeIfAbsent(ip, k -> new State());
        if (state.lockedUntil > now) return true;
        if (now - state.touched > FAIL_WINDOW_MILLIS) state.fails = 0;
        if (now - state.touched > STRIKE_MEMORY_MILLIS) state.strikes = 0;
        state.touched = now;
        state.fails++;
        if (state.fails >= maxAttempts) {
            state.strikes++;
            state.fails = 0;
            long lock = baseLockMillis << Math.min(state.strikes - 1, 12);
            state.lockedUntil = now + Math.min(lock, maxLockMillis);
            return true;
        }
        return false;
    }

    /**
     * A correct password does not clear the failures: otherwise someone owning one valid account on the same
     * address could interleave a successful login between every few guesses and never get locked.
     */
    public void recordSuccess(String ip) {
        // intentionally empty, see above
    }

    public void unlock(String ip) {
        states.remove(ip);
    }

    public int lockedCount() {
        long now = System.currentTimeMillis();
        return (int) states.values().stream().filter(s -> s.lockedUntil > now).count();
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        states.entrySet().removeIf(e -> e.getValue().lockedUntil <= now && now - e.getValue().touched > STRIKE_MEMORY_MILLIS);
    }
}
