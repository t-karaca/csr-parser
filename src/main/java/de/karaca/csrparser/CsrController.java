package de.karaca.csrparser;

import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1")
public class CsrController {

    private final ParserService parserService;

    public CsrController(ParserService parserService) {
        this.parserService = parserService;
    }

    @PostMapping("/csr")
    public CsrDetailsModel parseCsr(@RequestBody MultipartFile file) throws IOException {
        return parserService.parseWithBouncyCastle(file.getBytes());
    }
}
