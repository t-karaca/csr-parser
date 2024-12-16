package de.karaca.csrparser.decoder;

public final class ObjectIdentifiers {

    private ObjectIdentifiers() {}

    public static final String commonName = "2.5.4.3";
    public static final String country = "2.5.4.6";
    public static final String locality = "2.5.4.7";
    public static final String stateOrProvince = "2.5.4.8";
    public static final String organizationName = "2.5.4.10";
    public static final String organizationUnit = "2.5.4.11";

    public static final String pkcs9_emailAddress = "1.2.840.113549.1.9.1";
    public static final String pkcs9_unstructuredName = "1.2.840.113549.1.9.2";
    public static final String pkcs9_extensionRequest = "1.2.840.113549.1.9.14";

    public static final String ext_subjectAlternativeName = "2.5.29.17";

    public static final String md2WithRSAEncryption = "1.2.840.113549.1.1.2";
    public static final String md5WithRSAEncryption = "1.2.840.113549.1.1.4";
    public static final String sha1WithRSAEncryption = "1.2.840.113549.1.1.5";
    public static final String sha224WithRSAEncryption = "1.2.840.113549.1.1.14";
    public static final String sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
    public static final String sha384WithRSAEncryption = "1.2.840.113549.1.1.12";
    public static final String sha512WithRSAEncryption = "1.2.840.113549.1.1.13";
    public static final String sha512_224WithRSAEncryption = "1.2.840.113549.1.1.15";
    public static final String sha512_256WithRSAEncryption = "1.2.840.113549.1.1.16";

    // id-dsa-with-sha1
    public static final String idDSAWithSha1 = "1.2.840.10040.4.3";

    public static final String ecdsaPrefix = "1.2.840.10045.4";
    // ecdsa-with-SHA1
    public static final String ecdsaWithSHA1 = "1.2.840.10045.4.1";
    // ecdsa-with-SHA224
    public static final String ecdsaWithSHA224 = "1.2.840.10045.4.3.1";
    // ecdsa-with-SHA256
    public static final String ecdsaWithSHA256 = "1.2.840.10045.4.3.2";
    // ecdsa-with-SHA384
    public static final String ecdsaWithSHA384 = "1.2.840.10045.4.3.3";
    // ecdsa-with-SHA512
    public static final String ecdsaWithSHA512 = "1.2.840.10045.4.3.4";

    // rsaEncryption
    public static final String RSA = "1.2.840.113549.1.1.1";

    // id-dsa
    public static final String DSA = "1.2.840.10040.4.1";

    // dhpublicnumber
    public static final String DH = "1.2.840.10046.2.1";

    // id-keyExchangeAlgorithm
    public static final String KEA = "2.16.840.1.101.2.1.1.22";

    // id-ecPublicKey
    public static final String EC = "1.2.840.10045.2.1";

    /**
     * In DER encoding there are optionally parameters in an ASN.1 AlgorithmIdentifier.
     *
     * On public key algorithms these are set with specific parameters.
     *
     * On signature algorithms these are null or empty.
     * If it is empty the AlgorithmIdentifier SEQUENCE ends after the OBJECT IDENTIFIER.
     * If null, it is encoded explicitly as ASN.1 NULL (0x05 0x00)
     *
     * This is used to check if we have to read parameters or the next ASN.1 Object starts.
     *
     * @return true if there are no parameters encoded for this algorithm identifier, otherwise false
     **/
    public static boolean isParameterOmitted(String objectIdentifier) {
        switch (objectIdentifier) {
            case idDSAWithSha1:
                return true;
            case ecdsaWithSHA1:
                return true;
            case ecdsaWithSHA224:
                return true;
            case ecdsaWithSHA256:
                return true;
            case ecdsaWithSHA384:
                return true;
            case ecdsaWithSHA512:
                return true;
        }

        return false;
    }

    public static String getAlgorithmName(String algorithmId) {
        switch (algorithmId) {
            case RSA:
                return "rsaEncryption";
            case DSA:
                return "id-dsa";
            case DH:
                return "dhpublicnumber";
            case KEA:
                return "id-keyExchangeAlgorithm";
            case EC:
                return "id-ecPublicKey";

            case md2WithRSAEncryption:
                return "md2WithRSAEncryption";
            case md5WithRSAEncryption:
                return "md5WithRSAEncryption";
            case sha1WithRSAEncryption:
                return "sha1WithRSAEncryption";
            case sha224WithRSAEncryption:
                return "sha224WithRSAEncryption";
            case sha256WithRSAEncryption:
                return "sha256WithRSAEncryption";
            case sha384WithRSAEncryption:
                return "sha384WithRSAEncryption";
            case sha512WithRSAEncryption:
                return "sha512WithRSAEncryption";
            case sha512_224WithRSAEncryption:
                return "sha512-224WithRSAEncryption";
            case sha512_256WithRSAEncryption:
                return "sha512-256WithRSAEncryption";

            case idDSAWithSha1:
                return "id-dsa-with-sha1";

            case ecdsaWithSHA1:
                return "ecdsa-with-SHA1";
            case ecdsaWithSHA224:
                return "ecdsa-with-SHA224";
            case ecdsaWithSHA256:
                return "ecdsa-with-SHA256";
            case ecdsaWithSHA384:
                return "ecdsa-with-SHA384";
            case ecdsaWithSHA512:
                return "ecdsa-with-SHA512";
        }

        return algorithmId;
    }
}
