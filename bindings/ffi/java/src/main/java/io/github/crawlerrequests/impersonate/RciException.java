package io.github.crawlerrequests.impersonate;

import com.sun.jna.Pointer;

/**
 * An exception carrying the {@code {"error": "..."}} message the C ABI returned.
 */
public class RciException extends RuntimeException {
    public RciException(String message) {
        super(message);
    }
}
