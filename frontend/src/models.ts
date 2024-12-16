export interface CsrDetailsModel {
    issuer?: string;

    signatureAlgorithm: string;
    signatureAlgorithmId: string;
    publicKeyAlgorithm: string;
    publicKeyAlgorithmId: string;

    rsaKeyLength?: number;
    ecCurve?: string;

    commonName?: string;
    country?: string;
    locality?: string;
    stateOrProvince?: string;
    organizationName?: string;
    organizationUnit?: string;
    subjectAlternativeName?: string;
    emailAddress?: string;
}
