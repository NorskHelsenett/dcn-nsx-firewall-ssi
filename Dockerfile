FROM denoland/deno

# Path for EnvLoader config and secrets
ENV CONFIG_PATH=/app/config/config.yaml
ENV SECRETS_PATH=/app/secrets/secrets.yaml

# Create working directory
WORKDIR /app

# Copy source
COPY ./nhn_internal_ca_chain.crt /etc/ssl/certs/
COPY . .

# Compile the main app
RUN deno install --allow-scripts=npm:unix-dgram@2.0.6
RUN deno cache main.ts
# Deno test, requires valid config and secrets yaml
RUN ["deno", "task", "test"]
# Run the app development mode
RUN mkdir -p /app/logs && touch /app/logs/.keep
RUN mkdir -p /app/config && touch /app/config/.keep
RUN mkdir -p /app/secrets && touch /app/secrets/.keep
RUN chown deno:deno -R /app
RUN chmod u+s -R /app
RUN chmod g+s -R /app
RUN chmod 644 /etc/ssl/certs/nhn_internal_ca_chain.crt

# Switch to the 'deno' user provided by the base image
USER deno
# Run app in development mode
#CMD ["deno", "task", "dev"]
# Run the app in production mode
CMD ["deno", "task", "unsafe"]

#DEBUG Set the default command to run bash when the container starts, and user deno.
# Comment out the next 3 lines for removing debug
#RUN apt-get update && apt-get install -y curl iputils-ping
#CMD ["/bin/bash"]
#USER deno

# Cleanup secrets after build tests and run, comment out to run locally in docker.
RUN rm -f /app/config/*
RUN rm -f /app/secrets/*


