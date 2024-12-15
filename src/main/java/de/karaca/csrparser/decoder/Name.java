package de.karaca.csrparser.decoder;

import java.util.HashMap;
import java.util.Map;

public class Name {
    private final Map<String, String> attributes;

    public Name() {
        attributes = new HashMap<>();
    }

    public Name(Map<String, String> attributes) {
        this.attributes = new HashMap<>(attributes);
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }
}
