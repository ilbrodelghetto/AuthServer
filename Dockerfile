FROM openjdk:8-jdk-alpine
VOLUME [ "/tmp" ]
ARG JAVA_OPTS
ENV JAVA_OPTS=${JAVA_OPTS}
ADD target/*.jar auth-server.jar
EXPOSE 9100
ENTRYPOINT exec java ${JAVA_OPTS} -jar auth-server.jar
