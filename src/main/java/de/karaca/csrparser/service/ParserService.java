package de.karaca.csrparser.service;

import de.karaca.csrparser.exception.InvalidCsrException;
import de.karaca.csrparser.model.CsrDetailsModel;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class ParserService {
    private final String INVALID_CSR_MESSAGE = "File is not a valid Certificate Signing Request";

    private final ASN1ObjectIdentifier OID_COMMON_NAME = new ASN1ObjectIdentifier("2.5.4.3");
    private final ASN1ObjectIdentifier OID_COUNTRY = new ASN1ObjectIdentifier("2.5.4.6");
    private final ASN1ObjectIdentifier OID_LOCALITY = new ASN1ObjectIdentifier("2.5.4.7");
    private final ASN1ObjectIdentifier OID_STATE_OR_PROVINCE = new ASN1ObjectIdentifier("2.5.4.8");
    private final ASN1ObjectIdentifier OID_ORGANIZATION_NAME = new ASN1ObjectIdentifier("2.5.4.10");
    private final ASN1ObjectIdentifier OID_ORGANIZATION_UNIT = new ASN1ObjectIdentifier("2.5.4.11");
    private final ASN1ObjectIdentifier OID_EMAIL_ADDRESS = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;

    private static final Charset PEM_CHARSET = StandardCharsets.US_ASCII;

    private static final byte[] PEM_HEADER = "-----BEGIN CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);
    private static final byte[] PEM_FOOTER = "-----END CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);

    public CsrDetailsModel parseWithBouncyCastle(byte[] bytes) {
        try {
            PKCS10CertificationRequest req = readPKCS10(bytes);

            DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();

            String commonName = getAttributeFromName(req.getSubject(), OID_COMMON_NAME);
            String country = getAttributeFromName(req.getSubject(), OID_COUNTRY);
            String locality = getAttributeFromName(req.getSubject(), OID_LOCALITY);
            String stateOrProvince = getAttributeFromName(req.getSubject(), OID_STATE_OR_PROVINCE);
            String organizationName = getAttributeFromName(req.getSubject(), OID_ORGANIZATION_NAME);
            String organizationUnit = getAttributeFromName(req.getSubject(), OID_ORGANIZATION_UNIT);
            String emailAddress = getAttributeFromName(req.getSubject(), OID_EMAIL_ADDRESS);

            String subjectAlternativeName = null;

            Attribute[] extensions = req.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (extensions != null && extensions.length > 0) {
                ASN1Encodable[] values = extensions[0].getAttributeValues();
                if (values != null && values.length > 0) {
                    Extensions ext = Extensions.getInstance(values[0]);
                    GeneralNames names = GeneralNames.fromExtensions(ext, Extension.subjectAlternativeName);

                    subjectAlternativeName = Arrays.stream(names.getNames())
                            .map(this::generalNameToString)
                            .collect(Collectors.joining(", "));
                }
            }

            var builder = CsrDetailsModel.builder()
                    .signatureAlgorithm(finder.getAlgorithmName(req.getSignatureAlgorithm()))
                    .signatureAlgorithmId(
                            req.getSignatureAlgorithm().getAlgorithm().toString())
                    .publicKeyAlgorithm(finder.getAlgorithmName(
                            req.getSubjectPublicKeyInfo().getAlgorithm()))
                    .publicKeyAlgorithmId(req.getSubjectPublicKeyInfo()
                            .getAlgorithm()
                            .getAlgorithm()
                            .toString())
                    .commonName(commonName)
                    .country(country)
                    .locality(locality)
                    .stateOrProvince(stateOrProvince)
                    .organizationName(organizationName)
                    .organizationUnit(organizationUnit)
                    .subjectAlternativeName(subjectAlternativeName)
                    .emailAddress(emailAddress);

            AsymmetricKeyParameter keyParameter = PublicKeyFactory.createKey(req.getSubjectPublicKeyInfo());

            if (keyParameter instanceof RSAKeyParameters rsaKeyParameters) {
                builder.rsaKeyLength(rsaKeyParameters.getModulus().bitLength());
            }

            if (keyParameter instanceof ECPublicKeyParameters ecPublicKeyParameters) {
                System.out.println("Curve: "
                        + ecPublicKeyParameters
                                .getParameters()
                                .getCurve()
                                .getClass()
                                .getSimpleName());
            }

            return builder.build();

        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getAttributeFromName(X500Name name, ASN1ObjectIdentifier attributeId) {
        String result = Arrays.stream(name.getRDNs(attributeId))
                .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                .map(attribute -> attribute.getValue().toString())
                .collect(Collectors.joining(","));

        if (result == null || result.isBlank()) {
            return null;
        }

        return result;
    }

    public String generalNameToString(GeneralName name) {
        String tag =
                switch (name.getTagNo()) {
                    case GeneralName.iPAddress -> "IP";
                    case GeneralName.dNSName -> "DNS";
                    default -> Integer.toString(name.getTagNo());
                };

        return tag + ": " + name.getName();
    }

    public PKCS10CertificationRequest readPKCS10(byte[] bytes) {
        if (bytes.length >= PEM_HEADER.length
                && Arrays.equals(bytes, 0, PEM_HEADER.length, PEM_HEADER, 0, PEM_HEADER.length)) {
            // file is in PEM format

            String csr = new String(bytes, StandardCharsets.US_ASCII);

            try (PEMParser parser = new PEMParser(new StringReader(csr))) {
                return (PKCS10CertificationRequest) parser.readObject();
            } catch (IOException e) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE, e);
            }
        }

        try {
            // file is in DER format
            return new PKCS10CertificationRequest(bytes);
        } catch (IOException e) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE, e);
        }
    }

    private static final byte TAG_INTEGER = 0x02;
    private static final byte TAG_BIT_STRING = 0x03;
    private static final byte TAG_OCTET_STRING = 0x04;
    private static final byte TAG_NULL = 0x05;
    private static final byte TAG_OBJECT_IDENTIFIER = 0x06;
    private static final byte TAG_UTF8_STRING = 0x0C;
    private static final byte TAG_PRINTABLE_STRING = 0x13;
    private static final byte TAG_IA5_STRING = 0x16;
    private static final byte TAG_SEQUENCE = 0x30;
    private static final byte TAG_SET = 0x31;
    private static final byte TAG_EXPLICIT_CONTENT_SPECIFIC = (byte) 0xA0;

    public CsrDetailsModel parse(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(toDER(bytes));

        // CertificationRequest
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int length = readLength(buffer);

        // CertificationRequestInfo
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int criLength = readLength(buffer);

        // Version
        if (buffer.get() != TAG_INTEGER) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int versionLength = readLength(buffer);
        int version = readInt(buffer, versionLength);

        // Name (RDNSequence)
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int nameLength = readLength(buffer);
        int nameEnd = buffer.position() + nameLength;

        while (buffer.position() < nameEnd) {
            // RelativeDistinguishedName
            if (buffer.get() != TAG_SET) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            int rdnLength = readLength(buffer);

            // AttributeTypeAndValue
            if (buffer.get() != TAG_SEQUENCE) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            int atavLength = readLength(buffer);

            // AttributeType
            if (buffer.get() != TAG_OBJECT_IDENTIFIER) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            int typeLength = readLength(buffer);
            String oid = readOID(buffer, typeLength);
            System.out.println(oid);
            System.out.println(readString(buffer));
        }

        int publicKeyInfoStart = buffer.position();

        // SubjectPublicKeyInfo
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        buffer.mark();
        int lengthBytes = readNumLengthBytes(buffer);
        buffer.reset();
        int publicKeyInfoLength = readLength(buffer);
        // Java requires the key to be in SubjectPublicKeyInfo DER encoded format
        byte[] publicKeyInfoBytes = new byte[1 + lengthBytes + publicKeyInfoLength];

        int start = buffer.position();

        buffer.position(publicKeyInfoStart);
        buffer.get(publicKeyInfoBytes);

        buffer.position(start);

        try {
            // var key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyInfoBytes));
            var key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyInfoBytes));

            if (key instanceof ECPublicKey ecPublicKey) {
                log.info("alg {}", ecPublicKey.getParams());
            }

            log.info("Key", key);
        } catch (Exception e) {
            log.error("Ex: ", e);
        }

        // AlgorithmIdentifier
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        readLength(buffer);

        // algorithm
        if (buffer.get() != TAG_OBJECT_IDENTIFIER) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int algorithmLength = readLength(buffer);

        String algorithm = readOID(buffer, algorithmLength);
        System.out.println("Algo: " + algorithm);

        buffer.get();
        int pkParamsLength = readLength(buffer);
        buffer.position(buffer.position() + pkParamsLength);

        // subjectPublicKey
        if (buffer.get() != TAG_BIT_STRING) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int keyLength = readLength(buffer);

        byte[] publicKey = new byte[keyLength];
        buffer.get(publicKey);

        // Attributes
        if (buffer.get() != TAG_EXPLICIT_CONTENT_SPECIFIC) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int attributesLength = readLength(buffer);
        int attributesEnd = buffer.position() + attributesLength;
        while (buffer.position() < attributesEnd) {
            if (buffer.get() != TAG_SEQUENCE) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            readLength(buffer);

            // algorithm
            if (buffer.get() != TAG_OBJECT_IDENTIFIER) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            int idLength = readLength(buffer);

            String attributeId = readOID(buffer, idLength);
            log.info("id: {}", attributeId);

            if (buffer.get() != TAG_SET) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            int valuesLength = readLength(buffer);
            int valuesEnd = buffer.position() + valuesLength;

            while (buffer.position() < valuesEnd) {
                if (attributeId.equals("1.2.840.113549.1.9.2")) {
                    // unstructuredName
                    log.info("Value: {}", readString(buffer));
                } else if (attributeId.equals("1.2.840.113549.1.9.14")) {
                    // extensions
                    if (buffer.get() != TAG_SEQUENCE) {
                        throw new InvalidCsrException(INVALID_CSR_MESSAGE);
                    }

                    int extensionsLength = readLength(buffer);
                    int extensionsEnd = buffer.position() + extensionsLength;

                    while (buffer.position() < extensionsEnd) {
                        if (buffer.get() != TAG_SEQUENCE) {
                            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
                        }

                        readLength(buffer);

                        if (buffer.get() != TAG_OBJECT_IDENTIFIER) {
                            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
                        }

                        int extIdLength = readLength(buffer);

                        String extId = readOID(buffer, extIdLength);
                        log.info("extId: {}", extId);
                    }
                } else {
                    // skip unknown attribute
                    buffer.get();
                    int attrValueLength = readLength(buffer);
                    buffer.position(buffer.position() + attrValueLength);
                }
            }
        }

        // buffer.position(buffer.position() + len);

        // Signature AlgorithmIdentifier
        if (buffer.get() != TAG_SEQUENCE) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        readLength(buffer);

        // algorithm
        if (buffer.get() != TAG_OBJECT_IDENTIFIER) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int sigAlgorithmLength = readLength(buffer);

        String sigAlgorithm = readOID(buffer, sigAlgorithmLength);
        System.out.println("Signature Algo: " + sigAlgorithm);

        // ECDSA Signatures omit parameters field
        if (!sigAlgorithm.startsWith("1.2.840.10045.4")) {
            // parameters
            buffer.get();
            int sigParamsLength = readLength(buffer);
            buffer.position(buffer.position() + sigParamsLength);
        }

        // signature
        if (buffer.get() != TAG_BIT_STRING) {
            throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }

        int signatureLength = readLength(buffer);

        int unusedBits = buffer.get();

        byte[] signature = new byte[signatureLength - 1];
        buffer.get(signature);

        return null;
    }

    public int readNumLengthBytes(ByteBuffer buffer) {
        byte lengthByte = buffer.get();
        if ((lengthByte & 0x80) != 0) {
            return lengthByte & 0x7F + 1;
        }

        return 1;
    }

    public int readLength(ByteBuffer buffer) {
        byte lengthByte = buffer.get();
        if ((lengthByte & 0x80) != 0) {
            int numBytes = lengthByte & 0x7F;
            return readInt(buffer, numBytes);
        }

        return lengthByte;
    }

    public int readInt(ByteBuffer buffer, int numBytes) {
        if (numBytes > 4) {
            throw new InvalidCsrException("not supported");
        }

        byte[] lengthBytes = new byte[numBytes];
        buffer.get(lengthBytes);

        BigInteger lengthBigInt = new BigInteger(1, lengthBytes);

        return lengthBigInt.intValue();
    }

    public String readOID(ByteBuffer buffer, int numBytes) {
        StringBuilder builder = new StringBuilder();

        int end = buffer.position() + numBytes;

        int first = readOIDComponent(buffer, end - buffer.position());
        if (first < 40) {
            builder.append("0.");
            builder.append(first);
        } else if (first < 80) {
            builder.append("1.");
            builder.append(first - 40);
        } else {
            builder.append("2.");
            builder.append(first - 80);
        }

        while (end > buffer.position()) {
            builder.append('.');
            builder.append(readOIDComponent(buffer, end - buffer.position()));
        }

        return builder.toString();
    }

    public int readOIDComponent(ByteBuffer buffer, int remainingBytes) {
        byte b1 = buffer.get();
        if ((b1 & 0x80) != 0) {
            byte b2 = buffer.get();
            if ((b2 & 0x80) != 0) {
                // three bytes
                byte b3 = buffer.get();

                if ((b2 & 0x01) != 0) {
                    b3 |= 0x80;
                }

                b2 &= 0x7F;
                b2 >>>= 1;

                if ((b1 & 0x01) != 0) {
                    b2 |= 0x80;
                }

                b1 &= 0x7F;
                b1 >>>= 1;

                if ((b1 & 0x01) != 0) {
                    b2 |= 0x80;
                }

                b1 >>>= 1;

                return new BigInteger(1, new byte[] {b1, b2, b3}).intValue();
            } else {
                // two bytes
                if ((b1 & 0x01) != 0) {
                    b2 |= 0x80;
                }

                b1 &= 0x7F;
                b1 >>>= 1;

                return new BigInteger(1, new byte[] {b1, b2}).intValue();
            }
        }

        // single byte
        return b1;
    }

    public String readString(ByteBuffer buffer) {
        int tag = buffer.get();
        int length = readLength(buffer);

        byte[] bytes = new byte[length];
        buffer.get(bytes);

        switch (tag) {
            case TAG_IA5_STRING:
            case TAG_PRINTABLE_STRING:
                return new String(bytes, StandardCharsets.US_ASCII);
            case TAG_UTF8_STRING:
                return new String(bytes, StandardCharsets.UTF_8);
            default:
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
        }
    }

    public byte[] toDER(byte[] bytes) {
        if (bytes.length >= PEM_HEADER.length
                && Arrays.equals(bytes, 0, PEM_HEADER.length, PEM_HEADER, 0, PEM_HEADER.length)) {
            // file is in PEM format
            ByteBuffer buffer = ByteBuffer.wrap(bytes);

            buffer.position(PEM_HEADER.length);

            if (!readLineBreak(buffer)) {
                throw new InvalidCsrException(INVALID_CSR_MESSAGE);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            while (buffer.hasRemaining()
                    && buffer.remaining() >= PEM_FOOTER.length
                    && !Arrays.equals(
                            bytes,
                            buffer.position(),
                            buffer.position() + PEM_FOOTER.length,
                            PEM_FOOTER,
                            0,
                            PEM_FOOTER.length)) {
                int startPos = buffer.position();
                int endPos = buffer.position();
                while (!readLineBreak(buffer) && buffer.hasRemaining()) {
                    endPos++;
                    buffer.position(endPos);
                }

                baos.write(buffer.array(), startPos, endPos - startPos);
            }

            return Base64.getDecoder().decode(baos.toByteArray());
        }

        return bytes;
    }

    private boolean readLineBreak(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            return false;
        }

        // possible line breaks: \n \r \r\n

        byte b = buffer.get();
        if (b != '\n' && b != '\r') {
            return false;
        }

        if (b == '\r') {
            int pos = buffer.position();
            if (buffer.hasRemaining() && buffer.get() == '\n') {
                return true;
            }

            buffer.position(pos);
        }

        return true;
    }

    public ByteBuffer toDERBuffer(ByteBuffer buffer) {
        return null;
    }
}
