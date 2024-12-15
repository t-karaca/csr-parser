package de.karaca.csrparser.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import de.karaca.csrparser.exception.InvalidCsrException;
import de.karaca.csrparser.model.CsrDetailsModel;
import de.karaca.csrparser.service.ParserService;
import java.io.FileInputStream;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class ParserTest {
    @Autowired
    ParserService parserService;

    @Test
    void testCustom() throws Exception {
        // try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr.pem")) {
        try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr-san.pem")) {
            // try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr-small.pem")) {
            // try (InputStream inputStream = new FileInputStream("src/test/resources/ecdsa-csr.pem")) {
            parserService.parse(inputStream.readAllBytes());
        }
    }

    @Test
    void testOID() {
        // byte[] bytes = HexFormat.of().parseHex("2a864886f70d01010b");
        // String oid = parserService.readOID(ByteBuffer.wrap(bytes), bytes.length);
        // assertThat(oid).isEqualTo("1.2.840.113549.1.1.11");
    }

    @Test
    void testPEM() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr.pem")) {
            CsrDetailsModel model = parserService.parseWithBouncyCastle(inputStream.readAllBytes());

            assertThat(model.getCommonName()).isEqualTo("www.example.com");
            assertThat(model.getCountry()).isEqualTo("AU");
            assertThat(model.getLocality()).isEqualTo("Some-City");
            assertThat(model.getStateOrProvince()).isEqualTo("Some-State");
            assertThat(model.getOrganizationName()).isEqualTo("Internet Widgits Pty Ltd");
            assertThat(model.getOrganizationUnit()).isEqualTo("Company-Section");

            assertThat(model.getPublicKeyAlgorithm()).isEqualTo("RSA");
            assertThat(model.getSignatureAlgorithm()).isEqualTo("SHA256WITHRSA");
            assertThat(model.getRsaKeyLength()).isEqualTo(2048);

            assertThat(model.getEmailAddress()).isEqualTo("some@company.com");
        }
    }

    @Test
    void testDER() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr.der")) {
            CsrDetailsModel model = parserService.parseWithBouncyCastle(inputStream.readAllBytes());

            assertThat(model.getCommonName()).isEqualTo("www.example.com");
            assertThat(model.getCountry()).isEqualTo("AU");
            assertThat(model.getLocality()).isEqualTo("Some-City");
            assertThat(model.getStateOrProvince()).isEqualTo("Some-State");
            assertThat(model.getOrganizationName()).isEqualTo("Internet Widgits Pty Ltd");
            assertThat(model.getOrganizationUnit()).isEqualTo("Company-Section");

            assertThat(model.getPublicKeyAlgorithm()).isEqualTo("RSA");
            assertThat(model.getSignatureAlgorithm()).isEqualTo("SHA256WITHRSA");
            assertThat(model.getRsaKeyLength()).isEqualTo(2048);

            assertThat(model.getEmailAddress()).isEqualTo("some@company.com");
        }
    }

    @Test
    void testRSA4096() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr-4096.pem")) {
            CsrDetailsModel model = parserService.parseWithBouncyCastle(inputStream.readAllBytes());

            assertThat(model.getCommonName()).isEqualTo("Tarik");
            assertThat(model.getCountry()).isEqualTo("DE");
            assertThat(model.getLocality()).isEqualTo("Duisburg");
            assertThat(model.getStateOrProvince()).isEqualTo("NRW");
            assertThat(model.getOrganizationName()).isEqualTo("Karaca");
            assertThat(model.getOrganizationUnit()).isNull();

            assertThat(model.getPublicKeyAlgorithm()).isEqualTo("RSA");
            assertThat(model.getSignatureAlgorithm()).isEqualTo("SHA256WITHRSA");
            assertThat(model.getRsaKeyLength()).isEqualTo(4096);

            assertThat(model.getEmailAddress()).isNull();
        }
    }

    @Test
    void testECDSA() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/ecdsa-csr.pem")) {
            CsrDetailsModel model = parserService.parseWithBouncyCastle(inputStream.readAllBytes());

            assertThat(model.getCommonName()).isNull();
            assertThat(model.getCountry()).isEqualTo("AU");
            assertThat(model.getStateOrProvince()).isEqualTo("Some-State");
            assertThat(model.getOrganizationName()).isEqualTo("Internet Widgits Pty Ltd");
            assertThat(model.getOrganizationUnit()).isNull();

            // BouncyCastle does not provide a name for id-ecPublicKey
            assertThat(model.getPublicKeyAlgorithm()).isEqualTo("1.2.840.10045.2.1");
            assertThat(model.getSignatureAlgorithm()).isEqualTo("SHA256WITHECDSA");
            assertThat(model.getRsaKeyLength()).isNull();

            assertThat(model.getEmailAddress()).isNull();
        }
    }

    @Test
    void testSAN() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/rsa-csr-san.pem")) {
            CsrDetailsModel model = parserService.parseWithBouncyCastle(inputStream.readAllBytes());

            assertThat(model.getCommonName()).isEqualTo("example.com");
            assertThat(model.getCountry()).isEqualTo("DE");
            assertThat(model.getStateOrProvince()).isEqualTo("NRW");
            assertThat(model.getOrganizationName()).isEqualTo("Internet Widgits Pty Ltd");
            assertThat(model.getOrganizationUnit()).isNull();

            // BouncyCastle does not provide a name for id-ecPublicKey
            assertThat(model.getPublicKeyAlgorithm()).isEqualTo("RSA");
            assertThat(model.getSignatureAlgorithm()).isEqualTo("SHA256WITHRSA");
            assertThat(model.getRsaKeyLength()).isEqualTo(4096);

            assertThat(model.getSubjectAlternativeName()).isEqualTo("DNS: test.com, DNS: test.de");

            assertThat(model.getEmailAddress()).isNull();
        }
    }

    @Test
    void testInvalidCsr() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/ec-private-key.pem")) {
            assertThatExceptionOfType(InvalidCsrException.class)
                    .isThrownBy(() -> parserService.parseWithBouncyCastle(inputStream.readAllBytes()));
        }

        try (InputStream inputStream = new FileInputStream("src/test/resources/private-key.pem")) {
            assertThatExceptionOfType(InvalidCsrException.class)
                    .isThrownBy(() -> parserService.parseWithBouncyCastle(inputStream.readAllBytes()));
        }

        try (InputStream inputStream = new FileInputStream("src/test/resources/some-file")) {
            assertThatExceptionOfType(InvalidCsrException.class)
                    .isThrownBy(() -> parserService.parseWithBouncyCastle(inputStream.readAllBytes()));
        }
    }
}
