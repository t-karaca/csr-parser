FROM alpine:3.21.0 AS builder

RUN apk update && apk upgrade && apk --no-cache add nodejs npm openjdk17-jdk

COPY . /build

WORKDIR /build

RUN ./gradlew clean build

# --------------------------------------------

FROM alpine:3.21.0 AS final

RUN apk update && apk upgrade && apk add --no-cache openjdk17-jre-headless

COPY --from=builder /build/build/libs/csr-parser-*.jar /app/csr-parser.jar

WORKDIR /app

RUN mkdir /app/logs \
    && addgroup -g 1000 unprivileged \
    && adduser -u 1000 -G unprivileged -D -H -s /sbin/nologin unprivileged \
    && chown -R unprivileged:unprivileged /app/logs \
    && rm /bin/sh \
    && rm /bin/ash \
    && rm /sbin/apk \
    && rm /usr/bin/wget

USER unprivileged

CMD [ "java", "-Dfile.encoding=UTF8", "-jar", "/app/csr-parser.jar"]

