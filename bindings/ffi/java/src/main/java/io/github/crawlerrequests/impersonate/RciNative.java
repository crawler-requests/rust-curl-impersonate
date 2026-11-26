package io.github.crawlerrequests.impersonate;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Loads the shared library and keeps the one {@link RciLibrary} instance.
 *
 * <p>Resolution order:
 * <ol>
 *   <li>system property {@code rci.lib} (a library file, or the archive's
 *       {@code lib/} directory)</li>
 *   <li>environment variable {@code RCI_LIB}</li>
 *   <li>classpath resource {@code /rci/<platform>/<library name>} — what a jar
 *       that bundles the native library would ship</li>
 *   <li>the JNA loader search path ({@code jna.library.path}, then the OS
 *       defaults)</li>
 * </ol>
 */
public final class RciNative {

    private static volatile RciLibrary instance;

    private RciNative() {}

    /** The loaded library, with the ABI checked once. */
    public static RciLibrary library() {
        RciLibrary local = instance;
        if (local == null) {
            synchronized (RciNative.class) {
                local = instance;
                if (local == null) {
                    local = load();
                    checkAbi(local);
                    instance = local;
                }
            }
        }
        return local;
    }

    /** The library file name for this platform. */
    public static String libraryName() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("mac") || os.contains("darwin")) {
            return "librust_curl_impersonate_ffi.dylib";
        }
        if (os.contains("win")) {
            return "rust_curl_impersonate_ffi.dll";
        }
        return "librust_curl_impersonate_ffi.so";
    }

    private static RciLibrary load() {
        String explicit = System.getProperty("rci.lib");
        if (explicit == null || explicit.isBlank()) {
            explicit = System.getenv("RCI_LIB");
        }
        if (explicit != null && !explicit.isBlank()) {
            File file = new File(explicit);
            if (file.isDirectory()) {
                file = new File(file, libraryName());
            }
            if (!file.isFile()) {
                throw new IllegalStateException("no shared library at " + file.getAbsolutePath());
            }
            return Native.load(file.getAbsolutePath(), RciLibrary.class);
        }
        RciLibrary bundled = loadBundled();
        if (bundled != null) {
            return bundled;
        }
        // Let JNA search jna.library.path and the OS default paths.
        return Native.load("rust_curl_impersonate_ffi", RciLibrary.class);
    }

    /** A jar that bundles the native library ships it under /rci/&lt;platform&gt;/. */
    private static RciLibrary loadBundled() {
        String platform = platformResourceDirectory();
        String resource = "/rci/" + platform + "/" + libraryName();
        try (InputStream stream = RciNative.class.getResourceAsStream(resource)) {
            if (stream == null) {
                return null;
            }
            Path directory = Files.createTempDirectory("rci-native");
            Path file = directory.resolve(libraryName());
            Files.copy(stream, file, StandardCopyOption.REPLACE_EXISTING);
            directory.toFile().deleteOnExit();
            file.toFile().deleteOnExit();
            return Native.load(file.toAbsolutePath().toString(), RciLibrary.class);
        } catch (IOException error) {
            throw new IllegalStateException("cannot unpack " + resource, error);
        }
    }

    private static String platformResourceDirectory() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String osName = os.contains("mac") || os.contains("darwin") ? "macos"
                : os.contains("win") ? "windows" : "linux";
        String archName = arch.contains("aarch64") || arch.contains("arm64") ? "aarch64"
                : arch.contains("armv7") ? "armv7"
                : arch.contains("x86_64") || arch.contains("amd64") ? "x86_64"
                : arch.contains("i686") || arch.contains("x86") ? "i686" : arch;
        return osName + "-" + archName;
    }

    private static void checkAbi(RciLibrary library) {
        int version = library.rci_version();
        if (version < RciLibrary.ABI_VERSION) {
            throw new IllegalStateException(
                    "library has ABI " + version + ", this binding needs "
                            + RciLibrary.ABI_VERSION + " or newer");
        }
    }

    /**
     * Read a string the library returned and release it.
     *
     * @throws IllegalStateException when the library returned null
     */
    public static String take(Pointer text) {
        if (text == null) {
            throw new IllegalStateException("library returned a null string");
        }
        try {
            return text.getString(0, "UTF-8");
        } finally {
            library().rci_string_free(text);
        }
    }

    /** Read a returned UTF-8 string, or {@code null} for a browse string. */
    static String peek(Pointer text) {
        return text == null ? null : text.getString(0, "UTF-8");
    }

    static void freeIfAny(Pointer text) {
        if (text != null) {
            library().rci_string_free(text);
        }
    }

    /** Last client-construction error on this thread, or an empty string. */
    static String lastError() {
        String error = library().rci_last_error();
        return error == null ? "" : error;
    }

    // Kept for callers that pass UTF-8 bytes themselves.
    static byte[] utf8(String text) {
        return text == null ? null : text.getBytes(StandardCharsets.UTF_8);
    }
}
