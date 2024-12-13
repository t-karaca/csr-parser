package de.karaca.csrparser;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

@Service
public class ParserService {
    private static final byte[] PEM_HEADER = "-----BEGIN CERTIFICATE REQUEST-----".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PEM_FOOTER = "-----END CERTIFICATE REQUEST-----".getBytes(StandardCharsets.UTF_8);

    private static final int PEM_MAX_LINE_LENGTH = 64;

    public CsrDetailsModel parseBouncyCastle(byte[] bytes) {
        PKCS10CertificationRequest req = readPKCS10(bytes);

        DefaultAlgorithmNameFinder finder = new DefaultAlgorithmNameFinder();

        try {
            System.out.println("Signature algorithm: " + finder.getAlgorithmName(req.getSignatureAlgorithm()));
            System.out.println("                     "
                    + req.getSignatureAlgorithm().getAlgorithm().toString());
            System.out.println(req.getSubject().toString());

            var countryId = new ASN1ObjectIdentifier("2.5.4.6");
            var localityId = new ASN1ObjectIdentifier("2.5.4.7");
            var stateOrProvinceId = new ASN1ObjectIdentifier("2.5.4.8");
            var organizationNameId = new ASN1ObjectIdentifier("2.5.4.10");

            Arrays.stream(req.getSubject().getRDNs(countryId))
                    .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                    .map(x -> x.getValue().toString())
                    .map(x -> "Country: " + x)
                    .forEach(System.out::println);

            Arrays.stream(req.getSubject().getRDNs(localityId))
                    .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                    .map(x -> x.getValue().toString())
                    .map(x -> "Locale: " + x)
                    .forEach(System.out::println);

            Arrays.stream(req.getSubject().getRDNs(stateOrProvinceId))
                    .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                    .map(x -> x.getValue().toString())
                    .map(x -> "State or Province: " + x)
                    .forEach(System.out::println);

            Arrays.stream(req.getSubject().getRDNs(organizationNameId))
                    .flatMap(rdn -> Arrays.stream(rdn.getTypesAndValues()))
                    .map(x -> x.getValue().toString())
                    .map(x -> "Organization: " + x)
                    .forEach(System.out::println);

            System.out.println("Public key algorithm: "
                    + finder.getAlgorithmName(req.getSubjectPublicKeyInfo().getAlgorithm()));
            System.out.println("                      "
                    + req.getSubjectPublicKeyInfo()
                            .getAlgorithm()
                            .getAlgorithm()
                            .toString());

            AsymmetricKeyParameter keyParameter = PublicKeyFactory.createKey(req.getSubjectPublicKeyInfo());

            if (keyParameter instanceof RSAKeyParameters rsaKeyParameters) {
                System.out.println(rsaKeyParameters.getModulus().bitLength());
            }

        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return null;
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
