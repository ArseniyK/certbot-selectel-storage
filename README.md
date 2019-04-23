```
docker run --rm --name lets-encrypt -v /etc/letsencrypt/:/etc/letsencrypt/ -it arseniyk/certbot-selectel-storage --init \
--agree-tos \
-i certbot-selectel-storage:installer \
-a certbot-selectel-storage:auth \
--certbot-selectel-storage:auth-user <user> \
--certbot-selectel-storage:auth-key <key> \
--certbot-selectel-storage:auth-container <container> \
--certbot-selectel-storage:installer-user 64043 \
--certbot-selectel-storage:installer-key <key> \
-d <domain>```
