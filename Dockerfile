FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B -ntp -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN groupadd --system --gid 10001 mcs && useradd --system --uid 10001 --gid 10001 --home /nonexistent mcs
COPY --from=build --chown=10001:10001 /workspace/target/mcs-wallet-diagnostics.jar /app/app.jar
ENV JAVA_TOOL_OPTIONS="-Duser.timezone=UTC -Djava.io.tmpdir=/tmp -XX:MaxRAMPercentage=70"
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
