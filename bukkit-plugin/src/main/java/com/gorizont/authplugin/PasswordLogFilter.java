package com.gorizont.authplugin;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.ParameterizedMessage;

import java.util.regex.Pattern;

/**
 * Keeps passwords out of the server log.
 *
 * The server writes "X issued server command: /login secret" to the console and to logs/latest.log, and
 * hosting panels often keep those lines for weeks. This filter drops such lines for the commands that carry a
 * password. It is installed once on the root logger; on plugin disable it only switches itself off.
 */
final class PasswordLogFilter extends AbstractFilter {

    private static final Pattern SENSITIVE = Pattern.compile(
        "(?i)issued server command: /(login|l|register|reg|changepassword|cp|gorizontauth:\\w+)(\\s|$)");

    private static volatile PasswordLogFilter instance;
    private volatile boolean active = true;

    private PasswordLogFilter() {
        super(Result.DENY, Result.NEUTRAL);
    }

    static synchronized void install() {
        if (instance != null) {
            instance.active = true;
            return;
        }
        instance = new PasswordLogFilter();
        ((Logger) LogManager.getRootLogger()).addFilter(instance);
    }

    static void deactivate() {
        PasswordLogFilter current = instance;
        if (current != null) current.active = false;
    }

    private Result check(String message) {
        return active && message != null && SENSITIVE.matcher(message).find() ? Result.DENY : Result.NEUTRAL;
    }

    @Override
    public Result filter(LogEvent event) {
        if (event == null || event.getMessage() == null) return Result.NEUTRAL;
        return check(event.getMessage().getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Message message, Throwable t) {
        return check(message == null ? null : message.getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, String message, Object... params) {
        if (message == null) return Result.NEUTRAL;
        return check(params == null || params.length == 0 ? message : ParameterizedMessage.format(message, params));
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Object message, Throwable t) {
        return check(message == null ? null : message.toString());
    }
}
