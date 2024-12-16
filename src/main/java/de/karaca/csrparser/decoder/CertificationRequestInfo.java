package de.karaca.csrparser.decoder;

import lombok.Builder;
import lombok.Getter;
import org.springframework.util.MultiValueMap;

@Getter
@Builder
public class CertificationRequestInfo {
    private final int version;
    private final Name name;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final MultiValueMap<String, Object> attributes;

    @SuppressWarnings("unchecked") // will throw ClassCastException anyway if wrong type
    public <T> T getFirstAttribute(String identifier) {
        return (T) attributes.getFirst(identifier);
    }
}
