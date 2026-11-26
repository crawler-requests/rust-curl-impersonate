package io.github.crawlerrequests.impersonate;

import java.util.LinkedHashMap;
import java.util.Map;

/** The little JSON writing the binding does, kept free of dependencies. */
final class RciJsonWriter {

    private RciJsonWriter() {}

    /** Escape a string as a JSON string literal. */
    static String quote(String text) {
        StringBuilder out = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.append('"').toString();
    }

    /** Write one value; maps, lists, strings, numbers and booleans only. */
    static String value(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return quote((String) value);
        }
        if (value instanceof Boolean || value instanceof Number) {
            return String.valueOf(value);
        }
        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) value;
            StringBuilder out = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                out.append(quote(entry.getKey())).append(':').append(value(entry.getValue()));
            }
            return out.append('}').toString();
        }
        if (value instanceof Iterable) {
            StringBuilder out = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Iterable<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                out.append(value(item));
            }
            return out.append(']').toString();
        }
        if (value instanceof String[]) {
            Object[] array = (Object[]) value;
            StringBuilder out = new StringBuilder("[");
            for (int i = 0; i < array.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(value(array[i]));
            }
            return out.append(']').toString();
        }
        throw new IllegalArgumentException("cannot write " + value.getClass().getName());
    }

    /** Wrap one record into a library document, the shape rci_load_fingerprints wants. */
    static String wrap(Map<String, Object> record) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("fingerprints", java.util.List.of(record));
        return value(document);
    }
}
