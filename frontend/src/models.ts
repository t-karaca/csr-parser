export interface CsrDetailsModel {
    issuer?: string;

    signatureAlgorithm: string;
    signatureAlgorithmId: string;
    publicKeyAlgorithm: string;
    publicKeyAlgorithmId: string;

    rsaKeyLength?: number;

    commonName?: string;
    country?: string;
    locality?: string;
    stateOrProvince?: string;
    organizationName?: string;
    organizationUnit?: string;
    dnQualifier?: string;
    emailAddress?: string;
}
