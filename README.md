# Coclyco

## Goal

`cozy-coclyco` is designed to create Cozy instances, manage nginx vhost and Let's encrypt certificate issuance.

A single prime256v1 private key `/etc/ssl/private/cozy.pem` is used to issue certificates.
For each created instance with domain `<fqdn>`, it create

 * a `/etc/ssl/private/<fqdn>.crt` Let's encrypt certificate will be created
 * a `/etc/nginx/sites-available/<fqdn>` will be deployed and activated

The issued certificate must contain all subdomains needed for apps.
By default,

 * `<fqdn>`
 * `onboarding.<fqdn>`
 * `settings.<fqdn>`
 * `drive.<fqdn>`
 * `photos.<fqdn>`
 * `collect.<fqdn>`

are added to the certificate.

## Requirements

Before creating an instance and to be able to issue certificates with Let's Encrypt, you need to be able to pass the [ACME challenge](https://letsencrypt.org/how-it-works/), and so you need to :

 * configure your DNS to point all needed subdomains `<app>.<fqdn>` to your web server
 * serve `/etc/ssl/private/acme-challenge` as `http://*.<fqdn>/.well-known/acme-challenge/`

The best way to configure your web server is to configure your default vhost like below

	/etc/nginx/sites-available/default
	server {
		listen 80 default_server;
		listen [::]:80 default_server;

		root /var/www/html;
		server_name _;

		location /.well-known/acme-challenge/ {
			alias /etc/ssl/private/acme-challenge/;
		}

		location / {
			return 301 https://$host$request_uri;
		}
	}

## Usage

To create an instance

	cozy-coclyco create <fqdn> <email>

If you install an application on your Cozy, you need to regenerate the certificate to add the corresponding subdomain on it

	cozy-coclyco regenerate <fqdn>

To renew your certificates before expiration (Let's Encrypt certificates have 90 days life)

	cozy-coclyco renew

By default, the renewal is triggered each month by `/etc/cron.monthly/cozy-coclyco`

You can regenerate the nginx vhost with

	cozy-coclyco vhost <fqdn>

To backup a Cozy

	cozy-coclyco backup <fqdn>*

To restore a Cozy from a backup

	cozy-coclyco restore <fqdn> <archive.tar.xz>
