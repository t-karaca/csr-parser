package de.karaca.csrparser.exception;

import java.time.Instant;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ErrorMessage {
    private final Instant timestamp;
    private final String error;
}
