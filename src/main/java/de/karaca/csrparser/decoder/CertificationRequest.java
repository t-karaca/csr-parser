package de.karaca.csrparser.decoder;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class CertificationRequest {
    private final CertificationRequestInfo certificationRequestInfo;
    private final String signatureAlgorithm;
}
