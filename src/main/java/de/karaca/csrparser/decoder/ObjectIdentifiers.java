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

    // parameter must be NULL
    public static final String md2WithRSAEncryption = "1.2.840.113549.1.1.2";
    public static final String md5WithRSAEncryption = "1.2.840.113549.1.1.4";
    public static final String sha1WithRSAEncryption = "1.2.840.113549.1.1.5";
    public static final String sha224WithRSAEncryption = "1.2.840.113549.1.1.14";
    public static final String sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
    public static final String sha384WithRSAEncryption = "1.2.840.113549.1.1.12";
    public static final String sha512WithRSAEncryption = "1.2.840.113549.1.1.13";
    public static final String sha512_224WithRSAEncryption = "1.2.840.113549.1.1.15";
    public static final String sha512_256WithRSAEncryption = "1.2.840.113549.1.1.16";

    // parameter is omitted
    // id-dsa-with-sha1
    public static final String idDSAWithSha1 = "1.2.840.10040.4.3";

    // parameter is omitted
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
}
