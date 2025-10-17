FROM maven:3.9.11-eclipse-temurin-17 as builder

COPY . .

RUN mvn clean package

FROM quay.io/wildfly/wildfly:27.0.0.Final-jdk17

ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8787

COPY --from=builder target/ROOT.war /opt/jboss/wildfly/standalone/deployments/

EXPOSE 8080
EXPOSE 8787