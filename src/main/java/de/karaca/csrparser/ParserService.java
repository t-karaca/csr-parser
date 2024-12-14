package de.karaca.csrparser;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

@Service
public class ParserService {
    private static final Charset PEM_CHARSET = StandardCharsets.US_ASCII;

    private static final byte[] PEM_HEADER = "-----BEGIN CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);
    private static final byte[] PEM_FOOTER = "-----END CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);

    private static final int PEM_MAX_LINE_LENGTH = 64;

    public CsrDetailsModel parseWithBouncyCastle(byte[] bytes) {
        try {
            PKCS10CertificationRequest req = readPKCS10(bytes);

            DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();

            System.out.println(req.getSubject().toString());

            var countryId = new ASN1ObjectIdentifier("2.5.4.6");
            var localityId = new ASN1ObjectIdentifier("2.5.4.7");
            var stateOrProvinceId = new ASN1ObjectIdentifier("2.5.4.8");
            var organizationNameId = new ASN1ObjectIdentifier("2.5.4.10");

            String country = getAttributeFromName(req.getSubject(), countryId);
            String locality = getAttributeFromName(req.getSubject(), localityId);
            String stateOrProvince = getAttributeFromName(req.getSubject(), stateOrProvinceId);
            String organizationName = getAttributeFromName(req.getSubject(), organizationNameId);

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
                    .country(country)
                    .locality(locality)
                    .stateOrProvince(stateOrProvince)
                    .organizationName(organizationName);

            AsymmetricKeyParameter keyParameter = PublicKeyFactory.createKey(req.getSubjectPublicKeyInfo());

            if (keyParameter instanceof RSAKeyParameters rsaKeyParameters) {
                builder.rsaKeyLength(rsaKeyParameters.getModulus().bitLength());
            }

            return builder.build();

        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getAttributeFromName(X500Name name, ASN1ObjectIdentifier attributeId) {
        return Arrays.stream(name.getRDNs(attributeId))
                .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                .map(attribute -> attribute.getValue().toString())
                .collect(Collectors.joining(","));
    }

    public PKCS10CertificationRequest readPKCS10(byte[] bytes) {
        if (Arrays.equals(bytes, 0, PEM_HEADER.length, PEM_HEADER, 0, PEM_HEADER.length)) {
            // file is in PEM format

            String csr = new String(bytes, StandardCharsets.US_ASCII);

            try (PEMParser parser = new PEMParser(new StringReader(csr))) {
                return (PKCS10CertificationRequest) parser.readObject();
            } catch (IOException e) {
                // TODO: throw bad request
                throw new UncheckedIOException(e);
            }
        }

        try {
            // file is in DER format
            return new PKCS10CertificationRequest(bytes);
        } catch (IOException e) {
            // TODO: throw bad request
            throw new UncheckedIOException(e);
        }
    }

    public CsrDetailsModel parse(ByteBuffer buffer) {
        buffer.mark();

        byte[] headerBuffer = new byte[PEM_HEADER.length];
        buffer.get(headerBuffer);

        if (Arrays.equals(headerBuffer, PEM_HEADER)) {
            // file is in PEM format

            if (!readLineBreak(buffer)) {
                // TODO: invalid encoding
                throw new RuntimeException("Invalid encoding");
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            int startPos = buffer.position();
            int endPos = buffer.position();
            while (!readLineBreak(buffer) && buffer.hasRemaining()) {
                endPos++;
            }

            baos.write(buffer.array(), startPos, endPos - startPos);

            try (DataOutputStream dataOutputStream = new DataOutputStream(baos)) {

            } catch (Exception e) {
                // TODO: exception
            }

        } else {
            buffer.reset();
        }

        return null;
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
