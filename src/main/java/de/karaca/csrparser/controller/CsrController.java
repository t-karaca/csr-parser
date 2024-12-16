package de.karaca.csrparser.controller;

import de.karaca.csrparser.model.CsrDetailsModel;
import de.karaca.csrparser.service.BouncyCastleParserService;
import de.karaca.csrparser.service.CustomParserService;
import java.io.IOException;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class CsrController {

    private final BouncyCastleParserService bouncyCastleParserService;
    private final CustomParserService customParserService;

    public CsrController(BouncyCastleParserService bouncyCastleParserService, CustomParserService customParserService) {
        this.bouncyCastleParserService = bouncyCastleParserService;
        this.customParserService = customParserService;
    }

    /**
     * Parse CSR with BouncyCastle
     **/
    @PostMapping("/csr")
    public CsrDetailsModel parseCsr(@RequestBody Resource file) throws IOException {
        // reading files into a byte array is not really efficient but we are not expecting large files
        // and BouncyCastle requires a byte[] for DER and String for PEM anyway
        return bouncyCastleParserService.parse(file.getContentAsByteArray());
    }

    /**
     * Parse CSR with custom parser
     **/
    @PostMapping("/csr-custom")
    public CsrDetailsModel parseCsrCustom(@RequestBody Resource file) throws IOException {
        return customParserService.parse(file.getContentAsByteArray());
    }
}
