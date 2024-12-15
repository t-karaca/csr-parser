package de.karaca.csrparser.decoder;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class CertificationRequestInfo {
    private final int version;
    private final Name name;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
}
