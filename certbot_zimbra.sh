#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# GPLv3 license
# contributions: Jernej Jakob <jernej.jakob@gmail.com>

AGREE_TOS=""
NO_NGINX=false
DEPLOY_ONLY=false
PATCH_ONLY=false
RESTART_ZIMBRA=true
SERVICES="all"
WEBROOT="/opt/zimbra/data/nginx/html"
GITHUB_URL="https://github.com/jjakob/certbot-zimbra"
VERSION="v0.3"

## patches
# for "Release 8.8.8.GA.2009.UBUNTU16.64 UBUNTU16_64 FOSS edition, Patch 8.8.8_P2." as reported by zmcontrol -v.
read -r -d '' PATCH_Z88 <<'EOF'
diff -Naur templates.20180530_213444/nginx.conf.web.http.default.template templates/nginx.conf.web.http.default.template
--- templates.20180530_213444/nginx.conf.web.http.default.template      2018-05-30 21:34:50.754994945 +0200
+++ templates/nginx.conf.web.http.default.template      2018-05-30 21:44:31.456043263 +0200
@@ -406,4 +406,8 @@
         # for custom error pages, internal use only
         internal;
     }
+
+    location ^~ /.well-known/acme-challenge {
+        root /opt/zimbra/data/nginx/html;
+    }
 }
diff -Naur templates.20180530_213444/nginx.conf.web.https.default.template templates/nginx.conf.web.https.default.template
--- templates.20180530_213444/nginx.conf.web.https.default.template     2018-05-30 21:34:50.822997410 +0200
+++ templates/nginx.conf.web.https.default.template     2018-05-30 21:45:04.701248131 +0200
@@ -510,4 +510,8 @@
         # for custom error pages, internal use only
         internal;
     }
+
+    location ^~ /.well-known/acme-challenge {
+        root /opt/zimbra/data/nginx/html;
+    }
 }
diff -Naur templates.20180530_213444/nginx.conf.web.http.template templates/nginx.conf.web.http.template
--- templates.20180530_213444/nginx.conf.web.http.template      2018-05-30 21:34:50.826997555 +0200
+++ templates/nginx.conf.web.http.template      2018-05-30 21:45:48.206824832 +0200
@@ -407,5 +407,9 @@
         # for custom error pages, internal use only
         internal;
     }
+
+    location ^~ /.well-known/acme-challenge {
+        root /opt/zimbra/data/nginx/html;
+    }
 }
diff -Naur templates.20180530_213444/nginx.conf.web.https.template templates/nginx.conf.web.https.template
--- templates.20180530_213444/nginx.conf.web.https.template     2018-05-30 21:34:50.830997700 +0200
+++ templates/nginx.conf.web.https.template     2018-05-30 21:45:59.735242633 +0200
@@ -481,5 +481,9 @@
         # for custom error pages, internal use only
         internal;
     }
+
+    location ^~ /.well-known/acme-challenge {
+        root /opt/zimbra/data/nginx/html;
+    }
 }
EOF

read -r -d '' PATCH_Z87 <<'EOF'
diff -Naur templates_orig/nginx.conf.web.http.default.template templates/nginx.conf.web.http.default.template
--- templates_orig/nginx.conf.web.http.default.template	2017-10-01 20:30:23.022776735 +0200
+++ templates/nginx.conf.web.http.default.template	2017-10-01 20:39:04.619034013 +0200
@@ -65,6 +65,9 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
diff -Naur templates_orig/nginx.conf.web.https.default.template templates/nginx.conf.web.https.default.template
--- templates_orig/nginx.conf.web.https.default.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.https.default.template	2017-10-01 20:38:47.583025551 +0200
@@ -94,6 +94,9 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
diff -Naur templates_orig/nginx.conf.web.https.template templates/nginx.conf.web.https.template
--- templates_orig/nginx.conf.web.https.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.https.template	2017-10-01 20:35:34.062929705 +0200
@@ -95,6 +95,9 @@
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }

+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }
+
     location /
     {
         # Begin stray redirect hack
diff -Naur templates_orig/nginx.conf.web.http.template templates/nginx.conf.web.http.template
--- templates_orig/nginx.conf.web.http.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.http.template	2017-10-01 20:33:26.550866829 +0200
@@ -67,6 +67,9 @@
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }

+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }
+
     location /
     {
         # Begin stray redirect hack
EOF

read -r -d '' PATCH_Z86 <<'EOF'
+++ templates/nginx.conf.web.http.default.template	2017-09-10 09:57:59.420380580 +0200
@@ -39,6 +39,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.https.default.template templates/nginx.conf.web.https.default.template
--- templates_ORIG/nginx.conf.web.https.default.template	2015-12-16 09:51:45.196584572 +0100
+++ templates/nginx.conf.web.https.default.template	2017-09-10 09:58:23.839441900 +0200
@@ -55,6 +55,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.https.template templates/nginx.conf.web.https.template
--- templates_ORIG/nginx.conf.web.https.template	2015-12-02 15:36:35.322922195 +0100
+++ templates/nginx.conf.web.https.template	2017-09-10 09:59:17.917577714 +0200
@@ -56,6 +56,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.http.template templates/nginx.conf.web.http.template
--- templates_ORIG/nginx.conf.web.http.template	2014-12-15 22:18:51.000000000 +0100
+++ templates/nginx.conf.web.http.template	2017-09-10 10:00:10.216709079 +0200
@@ -66,6 +66,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
EOF

## end patches

## functions
# check executable certbot-auto / certbot / letsencrypt
function check_executable() {
	LEB_BIN=$(which certbot-auto certbot letsencrypt | head -n 1)
	# No way
	if [ -z "$LEB_BIN" ]; then
		echo "No letsencrypt/certbot binary found in $PATH";
		exit 1;
	fi
}

# version compare from  http://stackoverflow.com/a/24067243/738852
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

function bootstrap() {
    echo "Certbot-Zimbra $VERSION - $GITHUB_URL"

	if [ ! -x "/opt/zimbra/bin/zmcontrol" ]; then
		echo "/opt/zimbra/bin/zmcontrol not found"
		exit 1;
	fi
	DETECTED_ZIMBRA_VERSION=$(su - zimbra -c '/opt/zimbra/bin/zmcontrol -v' | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)
	if [ -z "$DETECTED_ZIMBRA_VERSION" ]; then
		echo "Unable to detect zimbra version"
		exit 1;
	fi
	echo "Detected Zimbra $DETECTED_ZIMBRA_VERSION"
	check_executable

	ZMHOSTNAME=$(su - zimbra -c '/opt/zimbra/bin/zmhostname')

	# If we got no domain from command line try using zimbra hostname
	# FIXME the prompt should be avoided in cron!
	if [ -z "$DOMAIN" ]; then
		DOMAIN=$ZMHOSTNAME
		echo "Using $ZMHOSTNAME ('zmhostname') as domain for certificate."
	fi

	CERTPATH="/etc/letsencrypt/live/$DOMAIN"

	# zimbraReverseProxyMailMode
	ZMODE=$(/opt/zimbra/bin/zmprov gs $DOMAIN zimbraReverseProxyMailMode | grep Mode | cut -f 2 -d " ")

	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		NGINX_BIN="/opt/zimbra/common/sbin/nginx"
	else
		NGINX_BIN="/opt/zimbra/nginx/sbin/nginx"
	fi
}

# Patch nginx, and check if it's installed
function patch_nginx() {
	# check if nginx is installed
	if [ ! -x $NGINX_BIN ]; then
		echo "zimbra-proxy package not present"
		exit 1
	fi

	grep -q 'acme-challenge' /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
	if [ $? -eq 0 ]; then
		# No need to patch
		return
	fi

    # check if patch binary is present
	PATCH_BIN=$(which patch)
	if [ -z "$PATCH_BIN" ]; then
		echo "No patch binary found. Please install OS 'patch' package";
		exit 1
	fi

	# Let's make a backup of zimbra's original templates
	BKDATE=$(date +"%Y%m%d_%H%M%S")
	echo "Making a backup of nginx templates in /opt/zimbra/conf/nginx/templates.$BKDATE"
	cp -r /opt/zimbra/conf/nginx/templates /opt/zimbra/conf/nginx/templates.$BKDATE

	# Simulate patching
	if version_gt $DETECTED_ZIMBRA_VERSION 8.8; then
		echo "$PATCH_Z88" | $PATCH_BIN --dry-run -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		echo "$PATCH_Z87" | $PATCH_BIN --dry-run -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.6; then
		echo "$PATCH_Z86" | $PATCH_BIN --dry-run -l -p1 -d /opt/zimbra/conf/nginx/templates/
	else
		echo "Your Zimbra version is not currently supported"
		exit 1;
	fi
	if [ $? -ne 0 ]; then
		echo "Patching test failed! Please see $GITHUB_URL/issues if this issue has already been reported or file a new one including the output above."
		exit 1;
	fi

	# DO patch
	if version_gt $DETECTED_ZIMBRA_VERSION 8.8; then
                echo "$PATCH_Z88" | $PATCH_BIN -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		echo "$PATCH_Z87" | $PATCH_BIN -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.6; then
		echo "$PATCH_Z86" | $PATCH_BIN -l -p1 -d /opt/zimbra/conf/nginx/templates/
	fi
	if [ $? -ne 0 ]; then
		echo "Patching zimbra's nginx failed! Please see $GITHUB_URL/issues if this issue has already been reported or file a new one including the output above."
		# Restore the backups
		cp /opt/zimbra/conf/nginx/templates.$BKDATE/* /opt/zimbra/conf/nginx/templates/
		echo "The original templates has been restored from /opt/zimbra/conf/nginx/templates.$BKDATE"
		exit 1
	fi

	# reload nginx config
	su - zimbra -c 'zmproxyctl restart'
	if [ $? -ne 0 ]; then
		echo "Something went wrong while restarting zimbra proxy component. Please see $GITHUB_URL/issues if this issue has already been reported or file a new one including the output above."
		exit 1
	fi
}

# perform the letsencrypt request and prepares the certs
function request_certificate() {

	# <8.7 didn't have nginx webroot
	if [ ! -d "$WEBROOT" ]; then
		mkdir -p $WEBROOT
		# owned by root on 8.8.8 by default
		#chown -R zimbra:zimbra $WEBROOT
	fi

	# Request our cert
	$LEB_BIN certonly $AGREE_TOS --webroot --webroot-path $WEBROOT -d $DOMAIN
	e=$?
	if [ $e -ne 0 ] ; then
		echo "$LEB_BIN returned an error: $e"
		exit 1
	fi
}

# copies stuff ready for zimbra deployment and test them
function prepare_certificate () {
	# Make zimbra accessible files
	mkdir /opt/zimbra/ssl/letsencrypt 2>/dev/null
	cp $CERTPATH/* /opt/zimbra/ssl/letsencrypt/
	chown -R zimbra:zimbra /opt/zimbra/ssl/letsencrypt/

	# Now we should have the chain. Let's create the "patched" chain suitable for Zimbra
	# The cert below comes from https://www.identrust.com/certificates/trustid/root-download-x3.html. It should be better to let the user fetch it?
	cat /opt/zimbra/ssl/letsencrypt/chain.pem - << 'EOF' >> /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
EOF

	# Test cert. 8.6 and below must use root
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'
	else
		/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	fi
	e=$?
	if [ $e -eq 1 ]; then
		echo "Unable to verify cert!"
		echo "zmcertmgr verifycrt exit status $e"
		exit 1;
	fi

}

# deploys certificate and restarts zimbra. ASSUMES prepare_certificate has been called already
function deploy_certificate() {
	# Backup old stuff
	cp -a /opt/zimbra/ssl/zimbra /opt/zimbra/ssl/zimbra.$(date "+%Y%m%d-%H%M")

	cp /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c "/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem -deploy ${SERVICES}"
	else
		/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	fi
	e=$?
	if [ $e -ne 0 ]; then
		echo "Deploying certificates failed!"
		echo "zmcertmgr deploycrt exit status $e"
		exit 1
	fi

	# Set ownership of nginx config template
	# FIXME: not needed?
        chown zimbra:zimbra /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default

	# Finally apply cert!
	if $RESTART_ZIMBRA; then
		su - zimbra -c 'zmcontrol restart'
		e=$?
	        if [ $e -ne 0 ]; then
			echo "Restarting zimbra failed!"
			echo "zmcontrol restart exit status $e"
		fi
	fi
}

function check_user () {
	if [ "$EUID" -ne 0 ]; then
		echo "This script must be run as root" 1>&2
		exit 1
	fi
}

function usage () {
	cat <<EOF
USAGE: $(basename $0) [OPTION]...
Options modifying behaviour:
	-d | --deploy-only: only deploy certificates, does not run letsencrypt or patch nginx
	-p | --patch-only: only patch nginx template files (useful in case they've been overwritten by an upgrade)
	-x | --no-nginx: don't check and patch zimbra's nginx
Misc:
        -a | --agree-tos: agree with the Terms of Service of Let's Encrypt
	-h | --hostname <hostname.foo>: hostname being requested. Default: output of 'zmhostname'
	-w | --webroot </path/to/webroot>: if there's a webserver other than zimbra's nginx (zimbra-proxy) on port 80, specify its webroot
	-s | --services <service_names>: the set of services to be used for a certificate,
	       	valid services are 'all' or any of: ldap,mailboxd,mta,proxy (see zmcertmgr help deploycrt)
	       	Default: 'all'
	-z | --no-zimbra-restart: do not restart zimbra after a certificate deployment

The default, when called without any behaviour-modifying options, is to:
- patch the nginx templates (for letsencrypt)
- request certificates (either fetch new ones or renew existing ones),
- deploy them into Zimbra
and finally
- do a Zimbra restart (to apply the deployed certificates).

It's invalid to use --patch-only in combination with --deploy-only or --no-nginx.

Do not put this script with default options into your crontab. It will go through the whole process of deploying the old certificates and restarting Zimbra even if none of the certificates are renewed.
For automated renewal, use certbot's pre/post/deploy-hooks, see $GITHUB_URL/blob/master/README.md#renewal .

If an error is encountered in any step of the process, the script prints a summary of the error and exits with a non-zero exit status.

Author: Lorenzo Milesi <maxxer@yetopen.it>
Contributor: Jernej Jakob <jernej.jakob@gmail.com>
Feedback, bugs and PR are welcome on GitHub: $GITHUB_URL

Disclaimer:
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
EOF
}
## end functions

# main flow
# parameters parsing http://stackoverflow.com/a/14203146/738852
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
		-h|--hostname)
			DOMAIN="$2"
			shift # past argument
			;;
		-x|--no-nginx)
			NO_NGINX=true
			;;
		-p|--patch-only)
			PATCH_ONLY=true
			;;
		-d|--deploy-only)
			DEPLOY_ONLY=true
			;;
		-w|--webroot)
			WEBROOT="$2"
			shift
			;;
		-a|--agree-tos)
			AGREE_TOS="--text --agree-tos --non-interactive"
			;;
		-s|--services)
			SERVICES="$2"
			shift
			;;
		-z|--no-zimbra-restart)
			RESTART_ZIMBRA=false
			;;
		--help)
			usage
			exit 0
			;;
		*)
			# unknown option
			echo "Unknown option: $key" >& 2
			echo "Try '$(basename $0) --help' for help."
			exit 1
			;;
	esac
	shift # past argument or value
done

if $DEPLOY_ONLY && $PATCH_ONLY; then
	usage
	exit 1
fi

if $PATCH_ONLY && ( $NO_NGINX || $DEPLOY_ONLY ); then
	usage
	exit 1
fi

# actions
check_user
bootstrap
$NO_NGINX || $DEPLOY_ONLY || patch_nginx
$PATCH_ONLY && exit 0
$DEPLOY_ONLY || request_certificate
prepare_certificate
deploy_certificate

exit 0
