package de.karaca.csrparser.exception;

public class InvalidCsrException extends RuntimeException {
    private static final String INVALID_CSR_MESSAGE = "File is not a valid Certificate Signing Request";

    public InvalidCsrException() {
        super(INVALID_CSR_MESSAGE);
    }

    public InvalidCsrException(String message) {
        super(message);
    }

    public InvalidCsrException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidCsrException(Throwable cause) {
        super(INVALID_CSR_MESSAGE, cause);
    }
}
