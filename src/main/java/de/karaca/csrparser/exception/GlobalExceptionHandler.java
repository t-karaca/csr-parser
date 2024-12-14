package de.karaca.csrparser.exception;

import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidCsrException.class)
    public ResponseEntity<ErrorMessage> invalidCsr(InvalidCsrException e) {
        log.debug("Caught exception: ", e);

        return ResponseEntity.badRequest()
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorMessage.builder()
                        .timestamp(Instant.now())
                        .error(e.getMessage())
                        .build());
    }
}
