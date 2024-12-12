package de.karaca.csrparser;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.stereotype.Service;

@Service
public class ParserService {
    private static final byte[] PEM_HEADER = "-----BEGIN CERTIFICATE REQUEST-----".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PEM_FOOTER = "-----END CERTIFICATE REQUEST-----".getBytes(StandardCharsets.UTF_8);

    private static final int PEM_MAX_LINE_LENGTH = 64;

    public CsrDetailsModel parse(ByteBuffer buffer) {
        buffer.mark();

        byte[] headerBuffer = new byte[PEM_HEADER.length];
        buffer.get(headerBuffer);

        if (Arrays.equals(headerBuffer, PEM_HEADER)) {
            // file is in PEM format

            if (buffer.get() != '\n') {
                // TODO: invalid encoding
            }

            ByteBuffer lineBuffer = ByteBuffer.allocate(PEM_MAX_LINE_LENGTH);

            while (buffer.hasRemaining()) {}

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            try (DataOutputStream dataOutputStream = new DataOutputStream(baos)) {

            } catch (Exception e) {
                // TODO: exception
            }

        } else {
            buffer.reset();
        }

        return null;
    }

    public ByteBuffer toASN1Buffer(ByteBuffer buffer) {
        return null;
    }
}
