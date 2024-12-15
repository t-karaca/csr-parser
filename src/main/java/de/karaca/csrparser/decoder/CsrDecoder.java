package de.karaca.csrparser.decoder;

import de.karaca.csrparser.exception.InvalidCsrException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Slf4j
public class CsrDecoder {
    private static final byte TAG_BOOLEAN = 0x01;
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

    private final ByteBuffer buffer;

    /**
     * Initialize a CsrDecoder with a DER encoded buffer
     **/
    public CsrDecoder(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    /**
     * Initialize a CsrDecoder with a DER encoded byte array
     **/
    public CsrDecoder(byte[] bytes) {
        this(ByteBuffer.wrap(bytes));
    }

    /**
     * Decode a PKCS#10 CertificationRequest from the given buffer.
     **/
    public CertificationRequest decode() {
        expectTag(TAG_SEQUENCE);
        readLength();

        CertificationRequestInfo certificationRequestInfo = decodeCertificationRequestInfo();

        String signatureAlgorithm = decodeAlgorithmIdentifier();

        return CertificationRequest.builder()
                .certificationRequestInfo(certificationRequestInfo)
                .signatureAlgorithm(signatureAlgorithm)
                .build();
    }

    private CertificationRequestInfo decodeCertificationRequestInfo() {
        expectTag(TAG_SEQUENCE);
        readLength();

        int version = decodeInteger();

        Name name = decodeName();

        SubjectPublicKeyInfo subjectPublicKeyInfo = decodeSubjectPublicKeyInfo();

        expectTag(TAG_EXPLICIT_CONTENT_SPECIFIC);
        int attributesLength = readLength();
        int attributesEnd = buffer.position() + attributesLength;

        MultiValueMap<String, Object> attributes = new LinkedMultiValueMap<>();

        while (buffer.position() < attributesEnd) {
            expectTag(TAG_SEQUENCE);
            readLength();

            String attributeId = decodeObjectIdentifier();

            expectTag(TAG_SET);
            int valuesLength = readLength();
            int valuesEnd = buffer.position() + valuesLength;

            while (buffer.position() < valuesEnd) {
                switch (attributeId) {
                    case ObjectIdentifiers.pkcs9_emailAddress:
                    case ObjectIdentifiers.pkcs9_unstructuredName:
                        attributes.add(attributeId, decodeString());
                        break;
                    case ObjectIdentifiers.pkcs9_extensionRequest:
                        attributes.add(attributeId, decodeExtensions());
                        break;
                    default: {
                        // skip unknown attribute
                        buffer.get();
                        int valueLength = readLength();
                        buffer.position(buffer.position() + valueLength);
                        break;
                    }
                }
            }
        }

        return CertificationRequestInfo.builder()
                .version(version)
                .name(name)
                .subjectPublicKeyInfo(subjectPublicKeyInfo)
                .build();
    }

    private SubjectPublicKeyInfo decodeSubjectPublicKeyInfo() {
        int encodedStart = buffer.position();

        expectTag(TAG_SEQUENCE);

        buffer.mark();
        int numLengthBytes = readNumLengthBytes();
        buffer.reset();

        int length = readLength();

        String algorithmIdentifier = decodeAlgorithmIdentifier();

        // Java requires the key to be in SubjectPublicKeyInfo DER encoded format
        byte[] encoded = new byte[1 + numLengthBytes + length];

        // read whole SubjectPublicKeyInfo into byte[]
        buffer.position(encodedStart);
        buffer.get(encoded);

        KeyFactory keyFactory = getKeyFactory(algorithmIdentifier);

        try {
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));

            return SubjectPublicKeyInfo.builder()
                    .algorithmIdentifier(algorithmIdentifier)
                    .publicKey(publicKey)
                    .build();
        } catch (InvalidKeySpecException e) {
            throw new InvalidCsrException(e);
        }
    }

    private String decodeAlgorithmIdentifier() {
        expectTag(TAG_SEQUENCE);
        readLength();

        String id = decodeObjectIdentifier();

        if (!ObjectIdentifiers.isParameterOmitted(id)) {
            // skip parameters (will be read by Java)
            buffer.get();
            int length = readLength();
            buffer.position(buffer.position() + length);
        }

        return id;
    }

    private Object decodeExtensions() {
        expectTag(TAG_SEQUENCE);

        int length = readLength();
        int end = buffer.position() + length;

        while (buffer.position() < end) {
            expectTag(TAG_SEQUENCE);
            readLength();

            String extensionId = decodeObjectIdentifier();

            int tag = buffer.get();
            if (tag == TAG_BOOLEAN) {
                // critical property from Extension
                int propLength = readLength();
                buffer.position(buffer.position() + propLength);

                // read next tag as this property is optional and defaults to false
                tag = buffer.get();
            }

            if (tag != TAG_OCTET_STRING) {
                throw new InvalidCsrException();
            }

            int extensionLength = readLength();

            switch (extensionId) {
                case ObjectIdentifiers.ext_subjectAlternativeName: {
                    var names = decodeGeneralNames();
                    log.info("{}", names);
                    break;
                }
                default:
                    // skip unknown extension
                    buffer.position(buffer.position() + extensionLength);
                    break;
            }
        }

        return null;
    }

    private List<GeneralName> decodeGeneralNames() {
        List<GeneralName> names = new ArrayList<>();

        expectTag(TAG_SEQUENCE);
        int length = readLength();
        int end = buffer.position() + length;

        while (buffer.position() < end) {
            int tag = buffer.get();
            if ((tag & 0x80) == 0) {
                throw new InvalidCsrException();
            }

            int choiceTag = tag & 0x7F;

            switch (choiceTag) {
                case GeneralName.TAG_DNS: {
                    String value = decodeIA5String();

                    names.add(new GeneralName(choiceTag, value));

                    break;
                }
                case GeneralName.TAG_IP: {
                    try {
                        InetAddress address = InetAddress.getByAddress(decodeOctetString());
                        String value = address.getHostAddress();
                        names.add(new GeneralName(choiceTag, value));
                    } catch (UnknownHostException e) {
                        // cannot happen since we are reading raw ip addresses
                    }

                    break;
                }
                default: {
                    // unsupported name tag, skip
                    buffer.get();
                    int nameLength = readLength();
                    buffer.position(buffer.position() + nameLength);

                    break;
                }
            }
        }

        return names;
    }

    private Void decodeNull() {
        expectTag(TAG_NULL);

        if (readLength() != 0) {
            throw new InvalidCsrException();
        }

        return null;
    }

    private int decodeInteger() {
        expectTag(TAG_INTEGER);
        int length = readLength();
        return readInt(length);
    }

    private String decodeString() {
        int tag = buffer.get();

        switch (tag) {
            case TAG_IA5_STRING:
            case TAG_PRINTABLE_STRING:
                return decodeIA5String();
            case TAG_UTF8_STRING:
                return decodeUTF8String();
            default:
                throw new InvalidCsrException();
        }
    }

    private String decodeIA5String() {
        int length = readLength();
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private String decodeUTF8String() {
        int length = readLength();
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] decodeOctetString() {
        expectTag(TAG_OCTET_STRING);
        int length = readLength();

        byte[] bytes = new byte[length];
        buffer.get(bytes);

        return bytes;
    }

    private String decodeObjectIdentifier() {
        expectTag(TAG_OBJECT_IDENTIFIER);

        int length = readLength();

        StringBuilder builder = new StringBuilder();

        int end = buffer.position() + length;

        int first = readObjectIdentifierComponent(end - buffer.position());
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

        while (buffer.position() < end) {
            builder.append('.');
            builder.append(readObjectIdentifierComponent(end - buffer.position()));
        }

        return builder.toString();
    }

    private int readObjectIdentifierComponent(int remainingBytes) {
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

    private Name decodeName() {
        Name name = new Name();

        expectTag(TAG_SEQUENCE);

        int length = readLength();
        int end = buffer.position() + length;

        while (buffer.position() < end) {
            // RelativeDistinguishedName
            expectTag(TAG_SET);
            readLength();

            // AttributeTypeAndValue
            expectTag(TAG_SEQUENCE);
            readLength();

            // AttributeType
            String type = decodeObjectIdentifier();
            String value = decodeString();

            name.getAttributes().put(type, value);
        }

        return name;
    }

    private void expectTag(byte tag) {
        if (buffer.get() != tag) {
            throw new InvalidCsrException();
        }
    }

    private int readNumLengthBytes() {
        byte lengthByte = buffer.get();
        if ((lengthByte & 0x80) != 0) {
            return (lengthByte & 0x7F) + 1;
        }

        return 1;
    }

    private int readLength() {
        byte lengthByte = buffer.get();
        if ((lengthByte & 0x80) != 0) {
            int numBytes = lengthByte & 0x7F;
            return readInt(numBytes);
        }

        return lengthByte;
    }

    private int readInt(int numBytes) {
        if (numBytes > 4) {
            throw new InvalidCsrException("not supported");
        }

        byte[] lengthBytes = new byte[numBytes];
        buffer.get(lengthBytes);

        BigInteger lengthBigInt = new BigInteger(1, lengthBytes);

        return lengthBigInt.intValue();
    }

    private static KeyFactory getKeyFactory(String algorithmId) {
        try {
            switch (algorithmId) {
                case ObjectIdentifiers.RSA:
                    return KeyFactory.getInstance("RSA");
                case ObjectIdentifiers.DSA:
                    return KeyFactory.getInstance("DSA");
                case ObjectIdentifiers.DH:
                    return KeyFactory.getInstance("DH");
                case ObjectIdentifiers.EC:
                    return KeyFactory.getInstance("EC");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidCsrException("Public Key algorithm not supported", e);
        }

        throw new InvalidCsrException("Public Key algorithm not supported");
    }
}
