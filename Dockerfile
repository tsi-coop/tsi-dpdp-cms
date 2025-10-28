# Use an official Jetty base image with Java 17
FROM jetty:jdk17

# Set environment variables for Jetty/Application (optional, but good practice)
ENV JETTY_BASE /var/lib/jetty
ENV JETTY_HOME /usr/local/jetty
ENV JETTY_RUN /tmp/jetty

RUN java -jar "$JETTY_HOME/start.jar" --add-modules=http,jdbc,jndi,ee10-deploy

# Switch to the 'jetty' user
USER jetty

# Copy your WAR file into Jetty's webapps directory
COPY target/tsi_dpdp_cms.war ${JETTY_BASE}/webapps/root.war

# Expose the default Jetty HTTP port
EXPOSE 8080

# The default CMD of the Jetty base image is usually sufficient to start Jetty.
# CMD ["java", "-jar", "$JETTY_HOME/start.jar"] # This is often the default or similar