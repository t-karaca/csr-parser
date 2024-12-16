package de.karaca.csrparser.service;

import de.karaca.csrparser.decoder.CertificationRequest;
import de.karaca.csrparser.decoder.CertificationRequestInfo;
import de.karaca.csrparser.decoder.CsrDecoder;
import de.karaca.csrparser.decoder.Extensions;
import de.karaca.csrparser.decoder.GeneralName;
import de.karaca.csrparser.decoder.Name;
import de.karaca.csrparser.decoder.ObjectIdentifiers;
import de.karaca.csrparser.exception.InvalidCsrException;
import de.karaca.csrparser.model.CsrDetailsModel;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class CustomParserService {

    private static final Charset PEM_CHARSET = StandardCharsets.US_ASCII;

    private static final byte[] PEM_HEADER = "-----BEGIN CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);
    private static final byte[] PEM_FOOTER = "-----END CERTIFICATE REQUEST-----".getBytes(PEM_CHARSET);

    public CsrDetailsModel parse(byte[] bytes) {
        CsrDecoder decoder = new CsrDecoder(toDER(bytes));

        CertificationRequest request = decoder.decodeCertificationRequest();
        CertificationRequestInfo requestInfo = request.getCertificationRequestInfo();
        Name name = requestInfo.getName();

        String publicKeyAlgorithmId = requestInfo.getSubjectPublicKeyInfo().getAlgorithmIdentifier();
        String signatureAlgorithmId = request.getSignatureAlgorithm();

        var builder = CsrDetailsModel.builder()
                .publicKeyAlgorithmId(publicKeyAlgorithmId)
                .publicKeyAlgorithm(ObjectIdentifiers.getAlgorithmName(publicKeyAlgorithmId))
                .signatureAlgorithmId(signatureAlgorithmId)
                .signatureAlgorithm(ObjectIdentifiers.getAlgorithmName(signatureAlgorithmId))
                .commonName(name.getAttribute(ObjectIdentifiers.commonName))
                .country(name.getAttribute(ObjectIdentifiers.country))
                .locality(name.getAttribute(ObjectIdentifiers.locality))
                .stateOrProvince(name.getAttribute(ObjectIdentifiers.stateOrProvince))
                .organizationName(name.getAttribute(ObjectIdentifiers.organizationName))
                .organizationUnit(name.getAttribute(ObjectIdentifiers.organizationUnit))
                .emailAddress(name.getAttribute(ObjectIdentifiers.pkcs9_emailAddress));

        Extensions extensions = requestInfo.<Extensions>getFirstAttribute(ObjectIdentifiers.pkcs9_extensionRequest);

        if (extensions != null) {
            var subjectAlternativeNames =
                    extensions.<List<GeneralName>>getFirst(ObjectIdentifiers.ext_subjectAlternativeName);

            if (subjectAlternativeNames != null) {
                String value = subjectAlternativeNames.stream()
                        .map(this::generalNameToString)
                        .collect(Collectors.joining(", "));

                builder.subjectAlternativeName(value);
            }
        }

        PublicKey publicKey = requestInfo.getSubjectPublicKeyInfo().getPublicKey();

        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            builder.rsaKeyLength(rsaPublicKey.getModulus().bitLength());
        }

        if (publicKey instanceof ECPublicKey ecPublicKey) {
            builder.ecCurve(ecPublicKey.getParams().toString());
        }

        return builder.build();
    }

    private String generalNameToString(GeneralName name) {
        String tag =
                switch (name.getTag()) {
                    case GeneralName.TAG_IP -> "IP";
                    case GeneralName.TAG_DNS -> "DNS";
                    default -> Integer.toString(name.getTag());
                };

        return tag + ": " + name.getValue();
    }

    private byte[] toDER(byte[] bytes) {
        if (bytes.length >= PEM_HEADER.length
                && Arrays.equals(bytes, 0, PEM_HEADER.length, PEM_HEADER, 0, PEM_HEADER.length)) {
            // file is in PEM format
            ByteBuffer buffer = ByteBuffer.wrap(bytes);

            buffer.position(PEM_HEADER.length);

            if (!readLineBreak(buffer)) {
                throw new InvalidCsrException();
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

    private static boolean readLineBreak(ByteBuffer buffer) {
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
