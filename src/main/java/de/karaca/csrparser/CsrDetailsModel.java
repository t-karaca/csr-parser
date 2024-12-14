package de.karaca.csrparser;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class CsrDetailsModel {
    private final String issuer;

    private final String signatureAlgorithm;
    private final String signatureAlgorithmId;
    private final String publicKeyAlgorithm;
    private final String publicKeyAlgorithmId;

    // boxed Integer because it should be nullable (not every key is an RSA key)
    private final Integer rsaKeyLength;

    private final String country;
    private final String locality;
    private final String stateOrProvince;
    private final String organizationName;
}
