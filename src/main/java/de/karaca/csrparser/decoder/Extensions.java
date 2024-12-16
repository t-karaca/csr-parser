package de.karaca.csrparser.decoder;

import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class Extensions {
    private final MultiValueMap<String, Object> entries;

    public Extensions() {
        entries = new LinkedMultiValueMap<>();
    }

    public Extensions(MultiValueMap<String, Object> attributes) {
        this.entries = new LinkedMultiValueMap<>(attributes);
    }

    public MultiValueMap<String, Object> getEntries() {
        return entries;
    }

    @SuppressWarnings("unchecked") // will throw ClassCastException anyway if wrong type
    public <T> T getFirst(String identifier) {
        return (T) entries.getFirst(identifier);
    }
}
