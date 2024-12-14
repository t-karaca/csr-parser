package de.karaca.csrparser.test;

import de.karaca.csrparser.CsrDetailsModel;
import de.karaca.csrparser.ParserService;
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
    void test() throws Exception {
        try (InputStream inputStream = new FileInputStream("src/test/resources/req.csr")) {
            CsrDetailsModel model = parserService.parseBouncyCastle(inputStream.readAllBytes());
        }
    }
}
