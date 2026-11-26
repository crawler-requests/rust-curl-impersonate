package io.github.crawlerrequests.impersonate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The smallest JSON reader that handles the C ABI's replies: objects, arrays,
 * strings (with escapes and \\uXXXX), numbers, booleans and null. Keeping it
 * here means the binding has no dependency beyond JNA, so a project that only
 * wants to call the library does not have to add Jackson or Gson.
 */
public final class RciJson {

    private final String text;
    private int index;

    private RciJson(String text) {
        this.text = text;
    }

    /** Parse a JSON document. Objects come back as {@link Map}, arrays as {@link List}. */
    public static Object parse(String json) {
        RciJson reader = new RciJson(json);
        Object value = reader.value();
        reader.skipWhitespace();
        if (reader.index != json.length()) {
            throw new IllegalArgumentException("trailing text at " + reader.index);
        }
        return value;
    }

    /** Parse a JSON object; anything else is an error. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object value = parse(json);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("not a JSON object: " + json);
        }
        return (Map<String, Object>) value;
    }

    private Object value() {
        skipWhitespace();
        if (index >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        char c = text.charAt(index);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return number();
        }
    }

    private Map<String, Object> object() {
        Map<String, Object> map = new LinkedHashMap<>();
        index++; // {
        skipWhitespace();
        if (peek() == '}') {
            index++;
            return map;
        }
        while (true) {
            skipWhitespace();
            String key = string();
            skipWhitespace();
            expectChar(':');
            map.put(key, value());
            skipWhitespace();
            char next = peek();
            index++;
            if (next == '}') {
                return map;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected , or } at " + index);
            }
        }
    }

    private List<Object> array() {
        List<Object> list = new ArrayList<>();
        index++; // [
        skipWhitespace();
        if (peek() == ']') {
            index++;
            return list;
        }
        while (true) {
            list.add(value());
            skipWhitespace();
            char next = peek();
            index++;
            if (next == ']') {
                return list;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected , or ] at " + index);
            }
        }
    }

    private String string() {
        expectChar('"');
        StringBuilder builder = new StringBuilder();
        while (true) {
            char c = text.charAt(index++);
            if (c == '"') {
                return builder.toString();
            }
            if (c != '\\') {
                builder.append(c);
                continue;
            }
            char escape = text.charAt(index++);
            switch (escape) {
                case '"': builder.append('"'); break;
                case '\\': builder.append('\\'); break;
                case '/': builder.append('/'); break;
                case 'b': builder.append('\b'); break;
                case 'f': builder.append('\f'); break;
                case 'n': builder.append('\n'); break;
                case 'r': builder.append('\r'); break;
                case 't': builder.append('\t'); break;
                case 'u':
                    builder.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                    index += 4;
                    break;
                default:
                    throw new IllegalArgumentException("bad escape \\" + escape);
            }
        }
    }

    private Object number() {
        int start = index;
        while (index < text.length() && "+-0123456789.eE".indexOf(text.charAt(index)) >= 0) {
            index++;
        }
        String spelling = text.substring(start, index);
        if (spelling.isEmpty()) {
            throw new IllegalArgumentException("not a JSON value at " + start);
        }
        if (spelling.contains(".") || spelling.contains("e") || spelling.contains("E")) {
            return Double.parseDouble(spelling);
        }
        return Long.parseLong(spelling);
    }

    private char peek() {
        if (index >= text.length()) {
            throw new IllegalArgumentException("unexpected end of JSON");
        }
        return text.charAt(index);
    }

    private void expectChar(char expected) {
        if (text.charAt(index) != expected) {
            throw new IllegalArgumentException("expected " + expected + " at " + index);
        }
        index++;
    }

    private void expect(String word) {
        if (!text.startsWith(word, index)) {
            throw new IllegalArgumentException("expected " + word + " at " + index);
        }
        index += word.length();
    }

    private void skipWhitespace() {
        while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
            index++;
        }
    }
}
