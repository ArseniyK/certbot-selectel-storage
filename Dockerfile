FROM certbot/certbot

COPY . src/certbot-selectel-storage

RUN pip install --constraint docker_constraints.txt --no-cache-dir --editable src/certbot-selectel-storage