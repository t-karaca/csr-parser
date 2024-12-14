package de.karaca.csrparser.exception;

public class InvalidCsrException extends RuntimeException {
    public InvalidCsrException() {
        super();
    }

    public InvalidCsrException(String message) {
        super(message);
    }

    public InvalidCsrException(String message, Throwable cause) {
        super(message, cause);
    }
}
