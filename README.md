# csr-parser

PKCS#10 CSR Parser with a Spring Boot backend and a React frontend.
The React frontend is built using Vite, TypeScript, shadcn ui and Tailwind CSS.

## Usage

The frontend is available at http://localhost:8080

Files can be uploaded with a file picker dialog or by drag and dropping to the browser.

Some test files created with OpenSSL are available at `src/test/resources`.

Swagger UI is available at http://localhost:8080/api/v1/swagger-ui

## Gradle Build

### Requirements

- Java 17 or higher
- NodeJS 20 or higher
- npm

### Building

Running the Gradle build will also trigger the npm build for the React frontend:

```bash
./gradlew clean build
```

This will output a fat jar with all dependencies and the React frontend bundled at `build/libs/csr-parser-1.0.0.jar` which can be run standalone:

```bash
java -jar build/libs/csr-parser-1.0.0.jar
```

The log files will be output in the `logs` directory.

## Docker Build

### Requirements

Only requirement is that docker is up and running.
The whole build will be executed inside Docker.
Therefore no Java or NodeJS is required on the host machine.

### Building

To run the docker build just execute:

```bash
docker build -t csr-parser:latest .
```

The image can then be started using the following command:

```bash
docker run -p 8080:8080 csr-parser:latest
```

The logs directory can also be mounted to the container so the log files are persisted on the host:

```bash
docker run -v ./logs/:/app/logs/ -p 8080:8080 csr-parser:latest
```
