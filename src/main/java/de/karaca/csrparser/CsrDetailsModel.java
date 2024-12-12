package de.karaca.csrparser;

public class CsrDetailsModel {
    private final String issuer;

    public CsrDetailsModel(String issuer) {
        this.issuer = issuer;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String issuer;

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public CsrDetailsModel build() {
            return new CsrDetailsModel(issuer);
        }
    }
}
