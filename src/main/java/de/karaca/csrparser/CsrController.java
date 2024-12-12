package de.karaca.csrparser;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1")
public class CsrController {
    @PostMapping("/csr")
    public CsrDetailsModel parseCsr(@RequestBody MultipartFile file) {
        return CsrDetailsModel.builder().build();
    }
}
