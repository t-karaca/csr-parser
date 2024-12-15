package de.karaca.csrparser.service;

import de.karaca.csrparser.decoder.CertificationRequest;
import de.karaca.csrparser.decoder.CsrDecoder;
import de.karaca.csrparser.exception.InvalidCsrException;
import de.karaca.csrparser.model.CsrDetailsModel;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

    public CsrDetailsModel parse(byte[] bytes) {
        CsrDecoder decoder = new CsrDecoder(toDER(bytes));

        CertificationRequest request = decoder.decode();

        return null;
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
}
