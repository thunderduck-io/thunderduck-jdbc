package io.thunderduck.jdbc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON parser + writer (no external dependency). Parses into
 * Map&lt;String,Object&gt; / List&lt;Object&gt; / String / Double / Boolean / null.
 *
 * <p>Internal to the driver. {@link #parseObject} and {@link #write} are public only so the
 * {@code io.thunderduck.jdbc.oidc} package can share this parser; they are not a supported API.
 */
public final class Json {

    private Json() {}

    // ---- parse ----
    static Object parse(String s) {
        Parser p = new Parser(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (!p.eof()) {
            throw new IllegalArgumentException("trailing JSON at " + p.pos);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String s) {
        return (Map<String, Object>) parse(s);
    }

    private static final class Parser {
        final String s;
        int pos;

        Parser(String s) { this.s = s; }

        boolean eof() { return pos >= s.length(); }

        char peek() { return s.charAt(pos); }

        void ws() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object value() {
            char c = peek();
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default: return number();
            }
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; // {
            ws();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                ws();
                String k = string();
                ws();
                if (s.charAt(pos) != ':') throw new IllegalArgumentException("expected ':' at " + pos);
                pos++;
                ws();
                m.put(k, value());
                ws();
                char c = s.charAt(pos++);
                if (c == '}') break;
                if (c != ',') throw new IllegalArgumentException("expected ',' or '}' at " + (pos - 1));
            }
            return m;
        }

        List<Object> array() {
            List<Object> a = new ArrayList<>();
            pos++; // [
            ws();
            if (peek() == ']') { pos++; return a; }
            while (true) {
                ws();
                a.add(value());
                ws();
                char c = s.charAt(pos++);
                if (c == ']') break;
                if (c != ',') throw new IllegalArgumentException("expected ',' or ']' at " + (pos - 1));
            }
            return a;
        }

        String string() {
            if (s.charAt(pos) != '"') throw new IllegalArgumentException("expected string at " + pos);
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\') {
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default: throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Object number() {
            int start = pos;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') pos++;
                else break;
            }
            return Double.valueOf(s.substring(start, pos));
        }

        void expect(String lit) {
            if (!s.startsWith(lit, pos)) throw new IllegalArgumentException("expected " + lit + " at " + pos);
            pos += lit.length();
        }
    }

    // ---- write (only what the driver sends: objects of String/Number/Boolean/null) ----
    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        writeTo(sb, v);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeTo(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { writeString(sb, (String) v); return; }
        if (v instanceof Boolean || v instanceof Number) { sb.append(v.toString()); return; }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, e.getKey());
                sb.append(':');
                writeTo(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object e : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                writeTo(sb, e);
            }
            sb.append(']');
            return;
        }
        writeString(sb, v.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
}
