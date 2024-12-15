package de.karaca.csrparser.decoder;

import java.security.PublicKey;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SubjectPublicKeyInfo {
    private final String algorithmIdentifier;
    private final PublicKey publicKey;
}
