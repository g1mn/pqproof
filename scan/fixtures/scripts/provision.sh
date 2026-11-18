#!/bin/sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/app/tls.key -out /etc/app/tls.crt -days 825 -subj /CN=app
openssl ecparam -genkey -name prime256v1 -out /etc/app/sign.key
ssh-keygen -t rsa -b 3072 -N '' -f /etc/app/deploy_key
keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -keystore /etc/app/app.jks
