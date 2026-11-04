package com.finsec.fuse.reimplementation.http;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;

/** Iterative JSON grammar inspection: no databinding, policy discovery, or recursive parsing. */
final class StrictJsonInspector {
    private StrictJsonInspector() {}

    static void verify(byte[] body, int maxDepth) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException invalid) {
            throw rejected();
        }
        new Parser(text, maxDepth).verify();
    }

    private static PublicHttpErrors.Rejected rejected() {
        return new PublicHttpErrors.Rejected(PublicHttpErrors.Error.INVALID_REQUEST);
    }

    private enum State {
        OBJECT_FIRST_KEY, OBJECT_KEY, OBJECT_COLON, OBJECT_VALUE, OBJECT_NEXT,
        ARRAY_FIRST_VALUE, ARRAY_VALUE, ARRAY_NEXT
    }

    private static final class Frame {
        State state;
        final Set<String> keys;
        Frame(boolean object) {
            state = object ? State.OBJECT_FIRST_KEY : State.ARRAY_FIRST_VALUE;
            keys = object ? new HashSet<>() : null;
        }
    }

    private static final class Parser {
        private final String text;
        private final int maxDepth;
        private final ArrayDeque<Frame> frames = new ArrayDeque<>();
        private int at;

        Parser(String text, int maxDepth) { this.text = text; this.maxDepth = maxDepth; }

        void verify() {
            boolean rootRead = false;
            while (true) {
                whitespace();
                if (frames.isEmpty()) {
                    if (rootRead) {
                        if (at != text.length()) throw rejected();
                        return;
                    }
                    rootRead = true;
                    value();
                    continue;
                }
                Frame frame = frames.peek();
                switch (frame.state) {
                    case OBJECT_FIRST_KEY -> {
                        if (take('}')) frames.pop();
                        else key(frame);
                    }
                    case OBJECT_KEY -> key(frame);
                    case OBJECT_COLON -> {
                        expect(':');
                        frame.state = State.OBJECT_VALUE;
                    }
                    case OBJECT_VALUE -> {
                        frame.state = State.OBJECT_NEXT;
                        value();
                    }
                    case OBJECT_NEXT -> {
                        if (take('}')) frames.pop();
                        else {
                            expect(',');
                            frame.state = State.OBJECT_KEY;
                        }
                    }
                    case ARRAY_FIRST_VALUE -> {
                        if (take(']')) frames.pop();
                        else {
                            frame.state = State.ARRAY_NEXT;
                            value();
                        }
                    }
                    case ARRAY_VALUE -> {
                        frame.state = State.ARRAY_NEXT;
                        value();
                    }
                    case ARRAY_NEXT -> {
                        if (take(']')) frames.pop();
                        else {
                            expect(',');
                            frame.state = State.ARRAY_VALUE;
                        }
                    }
                }
            }
        }

        private void key(Frame frame) {
            String key = string();
            if (!frame.keys.add(key)) throw rejected();
            frame.state = State.OBJECT_COLON;
        }

        private void value() {
            whitespace();
            if (at >= text.length()) throw rejected();
            char next = text.charAt(at);
            if (next == '{' || next == '[') {
                if (frames.size() >= maxDepth) {
                    throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.REQUEST_TOO_LARGE);
                }
                at++;
                frames.push(new Frame(next == '{'));
            } else if (next == '"') {
                string();
            } else if (next == 't') {
                literal("true");
            } else if (next == 'f') {
                literal("false");
            } else if (next == 'n') {
                literal("null");
            } else if (next == '-' || digit(next)) {
                number();
            } else {
                throw rejected();
            }
        }

        private String string() {
            expect('"');
            var decoded = new StringBuilder();
            while (at < text.length()) {
                char value = text.charAt(at++);
                if (value == '"') return decoded.toString();
                if (value < 0x20) throw rejected();
                if (value == '\\') {
                    if (at >= text.length()) throw rejected();
                    char escaped = text.charAt(at++);
                    switch (escaped) {
                        case '"', '\\', '/' -> decoded.append(escaped);
                        case 'b' -> decoded.append('\b');
                        case 'f' -> decoded.append('\f');
                        case 'n' -> decoded.append('\n');
                        case 'r' -> decoded.append('\r');
                        case 't' -> decoded.append('\t');
                        case 'u' -> {
                            char unit = unicodeUnit();
                            if (Character.isHighSurrogate(unit)) {
                                expect('\\'); expect('u');
                                char low = unicodeUnit();
                                if (!Character.isLowSurrogate(low)) throw rejected();
                                decoded.append(unit).append(low);
                            } else {
                                if (Character.isLowSurrogate(unit)) throw rejected();
                                decoded.append(unit);
                            }
                        }
                        default -> throw rejected();
                    }
                } else if (Character.isHighSurrogate(value)) {
                    if (at >= text.length() || !Character.isLowSurrogate(text.charAt(at))) throw rejected();
                    decoded.append(value).append(text.charAt(at++));
                } else {
                    if (Character.isLowSurrogate(value)) throw rejected();
                    decoded.append(value);
                }
            }
            throw rejected();
        }

        private char unicodeUnit() {
            if (text.length() - at < 4) throw rejected();
            int value = 0;
            for (int index = 0; index < 4; index++) {
                char unit = text.charAt(at++);
                int hex = unit >= 0x30 && unit <= 0x39 ? unit - 0x30
                        : unit >= 0x41 && unit <= 0x46 ? unit - 0x41 + 10
                        : unit >= 0x61 && unit <= 0x66 ? unit - 0x61 + 10 : -1;
                if (hex < 0) throw rejected();
                value = value * 16 + hex;
            }
            return (char) value;
        }

        private void number() {
            int start = at;
            take('-');
            if (!take('0')) {
                if (at >= text.length() || text.charAt(at) < '1' || text.charAt(at) > '9') throw rejected();
                digits();
            }
            if (take('.')) digits();
            if (take('e') || take('E')) {
                if (!take('+')) take('-');
                digits();
            }
            try {
                if (!Double.isFinite(Double.parseDouble(text.substring(start, at)))) throw rejected();
            } catch (NumberFormatException invalid) {
                throw rejected();
            }
        }

        private void digits() {
            int start = at;
            while (at < text.length() && digit(text.charAt(at))) at++;
            if (at == start) throw rejected();
        }

        private static boolean digit(char value) { return value >= '0' && value <= '9'; }

        private void literal(String value) {
            if (!text.startsWith(value, at)) throw rejected();
            at += value.length();
        }

        private void whitespace() {
            while (at < text.length()) {
                char value = text.charAt(at);
                if (value != ' ' && value != '\t' && value != '\n' && value != '\r') return;
                at++;
            }
        }

        private boolean take(char expected) {
            if (at < text.length() && text.charAt(at) == expected) { at++; return true; }
            return false;
        }

        private void expect(char expected) {
            if (!take(expected)) throw rejected();
        }
    }
}
