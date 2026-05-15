FROM eclipse-temurin:17-jdk-alpine AS builder
WORKDIR /build

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

RUN chmod +x mvnw && ./mvnw dependency:go-offline -B

COPY src src
RUN ./mvnw clean package -DskipTests -B

FROM quay.io/wildfly/wildfly:27.0.0.Final-jdk17

ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8787

COPY --from=builder /build/target/ROOT.war /opt/jboss/wildfly/standalone/deployments/

EXPOSE 8080 8787