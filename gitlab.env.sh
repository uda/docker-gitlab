#@IgnoreInspection BashAddShebang
# Set this to true to enable entrypoint debugging.
DEBUG=

# TimeZone
TZ=

# The hostname of the GitLab server. Defaults to localhost
GITLAB_HOST=
# If you are migrating from GitLab CI use this parameter to configure the redirection to the GitLab service so that your
# existing runners continue to work without any changes. No defaults.
GITLAB_CI_HOST=
# The port of the GitLab server. This value indicates the public port on which the GitLab application will be accessible
# on the network and appropriately configures GitLab to generate the correct urls. It does not affect the port on which
# the internal nginx server will be listening on. Defaults to 443 if GITLAB_HTTPS=true, else defaults to 80.
GITLAB_PORT=

# Encryption key for GitLab CI secret variables, as well as import credentials, in the database. Ensure that your key is
# at least 32 characters long and that you don't lose it. You can generate one using pwgen -Bsv1 64. If you are
# migrating from GitLab CI, you need to set this value to the value of GITLAB_CI_SECRETS_DB_KEY_BASE. No defaults.
GITLAB_SECRETS_DB_KEY_BASE=
# Encryption key for session secrets. Ensure that your key is at least 64 characters long and that you don't lose it.
# This secret can be rotated with minimal impact - the main effect is that previously-sent password reset emails will no
# longer work. You can generate one using pwgen -Bsv1 64. No defaults.
GITLAB_SECRETS_SECRET_KEY_BASE=
# Encryption key for OTP related stuff with GitLab. Ensure that your key is at least 64 characters long and that you
# don't lose it. If you lose or change this secret, 2FA will stop working for all users.
# You can generate one using pwgen -Bsv1 64. No defaults.
GITLAB_SECRETS_OTP_KEY_BASE=

# Configure the timezone for the gitlab application. This configuration does not effect cron jobs. Defaults to UTC.
# See the list of acceptable values.
GITLAB_TIMEZONE=
# The password for the root user on firstrun. Defaults to 5iveL!fe.
GITLAB_ROOT_PASSWORD=

# The email for the root user on firstrun. Defaults to admin@example.com
GITLAB_ROOT_EMAIL=
# The email address for the GitLab server. Defaults to value of SMTP_USER, else defaults to example@example.com.
GITLAB_EMAIL=
# The name displayed in emails sent out by the GitLab mailer. Defaults to GitLab.
GITLAB_EMAIL_DISPLAY_NAME=
# The reply-to address of emails sent out by GitLab. Defaults to value of GITLAB_EMAIL,
# else defaults to noreply@example.com.
GITLAB_EMAIL_REPLY_TO=
# The e-mail subject suffix used in e-mails sent by GitLab. No defaults.
GITLAB_EMAIL_SUBJECT_SUFFIX=
# Enable or disable gitlab mailer. Defaults to the SMTP_ENABLED configuration.
GITLAB_EMAIL_ENABLED=
# The incoming email address for reply by email. Defaults to the value of IMAP_USER, else defaults to reply@example.com.
# Please read the reply by email documentation to curretly set this parameter.
GITLAB_INCOMING_EMAIL_ADDRESS=
# Enable or disable gitlab reply by email feature. Defaults to the value of IMAP_ENABLED.
GITLAB_INCOMING_EMAIL_ENABLED=

# Enable or disable user signups (first run only). Default is true.
GITLAB_SIGNUP_ENABLED=
# Set default projects limit. Defaults to 100.
GITLAB_PROJECTS_LIMIT=
# Enable or disable ability for users to change their username. Defaults to true.
GITLAB_USERNAME_CHANGE=
# Enable or disable ability for users to create groups. Defaults to true.
GITLAB_CREATE_GROUP=
# Set if issues feature should be enabled by default for new projects. Defaults to true.
GITLAB_PROJECTS_ISSUES=
# Set if merge requests feature should be enabled by default for new projects. Defaults to true.
GITLAB_PROJECTS_MERGE_REQUESTS=
# Set if wiki feature should be enabled by default for new projects. Defaults to true.
GITLAB_PROJECTS_WIKI=
# Set if snippets feature should be enabled by default for new projects. Defaults to false.
GITLAB_PROJECTS_SNIPPETS=
# Set if builds feature should be enabled by default for new projects. Defaults to true.
GITLAB_PROJECTS_BUILDS=
# Set if container_registry feature should be enabled by default for new projects. Defaults to true.
GITLAB_PROJECTS_CONTAINER_REGISTRY=

# Sets the timeout for webhooks. Defaults to 10 seconds.
GITLAB_WEBHOOK_TIMEOUT=
# Sets the timeout for git commands. Defaults to 10 seconds.
GITLAB_TIMEOUT=
# Maximum size (in bytes) of a git object (eg. a commit) in bytes. Defaults to 20971520, i.e. 20 megabytes.
GITLAB_MAX_OBJECT_SIZE=
# Enable or disable broken build notification emails. Defaults to true
GITLAB_NOTIFY_ON_BROKEN_BUILDS=
# Add pusher to recipients list of broken build notification emails. Defaults to false
GITLAB_NOTIFY_PUSHER=

# The git repositories folder in the container. Defaults to /home/git/data/repositories
GITLAB_REPOS_DIR=
# The backup folder in the container. Defaults to /home/git/data/backups
GITLAB_BACKUP_DIR=
# The build traces directory. Defaults to /home/git/data/builds
GITLAB_BUILDS_DIR=
# The repository downloads directory. A temporary zip is created in this directory when users click Download Zip on a
# project. Defaults to /home/git/data/tmp/downloads.
GITLAB_DOWNLOADS_DIR=
# The directory to store the build artifacts. Defaults to /home/git/data/shared
GITLAB_SHARED_DIR=

# Enable/Disable GitLab artifacts support. Defaults to true.
GITLAB_ARTIFACTS_ENABLED=
# Directory to store the artifacts. Defaults to $GITLAB_SHARED_DIR/artifacts
GITLAB_ARTIFACTS_DIR=
# Enable/Disable Git LFS support. Defaults to true.
GITLAB_LFS_ENABLED=
# Directory to store the lfs-objects. Defaults to $GITLAB_SHARED_DIR/lfs-objects
GITLAB_LFS_OBJECTS_DIR=

# Enable/Disable GitLab Mattermost for Add Mattermost button. Defaults to false.
GITLAB_MATTERMOST_ENABLED=
# Sets Mattermost URL. Defaults to https://mattermost.example.com.
GITLAB_MATTERMOST_URL=

# Setup cron job to automatic backups. Possible values disable, daily, weekly or monthly. Disabled by default
GITLAB_BACKUP_SCHEDULE=
# Configure how long (in seconds) to keep backups before they are deleted. By default when automated backups are
# disabled backups are kept forever (0 seconds), else the backups expire in 7 days (604800 seconds).
GITLAB_BACKUP_EXPIRY=
# Specify the PostgreSQL schema for the backups. No defaults, which means that all schemas will be backed up. see #524
GITLAB_BACKUP_PG_SCHEMA=
# Sets the permissions of the backup archives. Defaults to 0600. See
GITLAB_BACKUP_ARCHIVE_PERMISSIONS=
# Set a time for the automatic backups in HH:MM format. Defaults to 04:00.
GITLAB_BACKUP_TIME=
# Specified sections are skipped by the backups. Defaults to empty, i.e. lfs,uploads. See
GITLAB_BACKUP_SKIP=

# The ssh host. Defaults to GITLAB_HOST.
GITLAB_SSH_HOST=
# The ssh port number. Defaults to 22.
GITLAB_SSH_PORT=

# The relative url of the GitLab server, e.g. /git. No default.
GITLAB_RELATIVE_URL_ROOT=
# Add IP address reverse proxy to trusted proxy list, otherwise users will appear signed in from that address.
# Currently only a single entry is permitted. No defaults.
GITLAB_TRUSTED_PROXIES=

# Enables the GitLab Container Registry. Defaults to false.
GITLAB_REGISTRY_ENABLED=
# Sets the GitLab Registry Host. Defaults to registry.example.com
GITLAB_REGISTRY_HOST=
# Sets the GitLab Registry Port. Defaults to 443.
GITLAB_REGISTRY_PORT=
# Sets the GitLab Registry API URL. Defaults to http://localhost:5000
GITLAB_REGISTRY_API_URL=
# Sets the GitLab Registry Key Path. Defaults to config/registry.key
GITLAB_REGISTRY_KEY_PATH=
# Directory to store the container images will be shared with registry. Defaults to $GITLAB_SHARED_DIR/registry
GITLAB_REGISTRY_DIR=
# Sets the GitLab Registry Issuer. Defaults to gitlab-issuer.
GITLAB_REGISTRY_ISSUER=

# Set to true to enable https support, disabled by default.
GITLAB_HTTPS=
# Set to true when using self signed ssl certificates. false by default.
SSL_SELF_SIGNED=
# Location of the ssl certificate. Defaults to /home/git/data/certs/gitlab.crt
SSL_CERTIFICATE_PATH=
# Location of the ssl private key. Defaults to /home/git/data/certs/gitlab.key
SSL_KEY_PATH=
# Location of the dhparam file. Defaults to /home/git/data/certs/dhparam.pem
SSL_DHPARAM_PATH=
# Enable verification of client certificates using the SSL_CA_CERTIFICATES_PATH file. Defaults to false
SSL_VERIFY_CLIENT=
# List of SSL certificates to trust. Defaults to /home/git/data/certs/ca.crt.
SSL_CA_CERTIFICATES_PATH=
# Location of the ssl private key for gitlab container registry. Defaults to /home/git/data/certs/registry.key
SSL_REGISTRY_KEY_PATH=
# Location of the ssl certificate for the gitlab container registry. Defaults to /home/git/data/certs/registry.crt
SSL_REGISTRY_CERT_PATH=
# List of supported SSL ciphers: Defaults to ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4
SSL_CIPHERS=

# The number of nginx workers to start. Defaults to 1.
NGINX_WORKERS=
# Sets the bucket size for the server names hash tables. This is needed when you have long server_names or your an error
# message from nginx like nginx: [emerg] could not build server_names_hash, you should increase
# server_names_hash_bucket_size:... It should be only increment by a power of 2. Defaults to 32.
NGINX_SERVER_NAMES_HASH_BUCKET_SIZE=
# Advanced configuration option for turning off the HSTS configuration. Applicable only when SSL is in use.
# Defaults to true. See #138 for use case scenario.
NGINX_HSTS_ENABLED=
# Advanced configuration option for setting the HSTS max-age in the gitlab nginx vHost configuration.
# Applicable only when SSL is in use. Defaults to 31536000.
NGINX_HSTS_MAXAGE=
# Enable proxy_buffering. Defaults to off.
NGINX_PROXY_BUFFERING=
# Enable X-Accel-Buffering header. Default to no
NGINX_ACCEL_BUFFERING=
# Advanced configuration option for the proxy_set_header X-Forwarded-Proto setting in the gitlab nginx vHost
# configuration. Defaults to https when GITLAB_HTTPS is true, else defaults to $scheme.
NGINX_X_FORWARDED_PROTO=

# The hostname of the redis server. Defaults to localhost
REDIS_HOST=
# The connection port of the redis server. Defaults to 6379.
REDIS_PORT=
# The redis database number. Defaults to '0'.
REDIS_DB_NUMBER=

# The number of unicorn workers to start. Defaults to 3.
UNICORN_WORKERS=
# Sets the timeout of unicorn worker processes. Defaults to 60 seconds.
UNICORN_TIMEOUT=

# The number of concurrent sidekiq jobs to run. Defaults to 25
SIDEKIQ_CONCURRENCY=
# Timeout for sidekiq shutdown. Defaults to 4
SIDEKIQ_SHUTDOWN_TIMEOUT=
# Non-zero value enables the SidekiqMemoryKiller. Defaults to 1000000.
# For additional options refer Configuring the MemoryKiller
SIDEKIQ_MEMORY_KILLER_MAX_RSS=

# The database type. Possible values: mysql2, postgresql. Defaults to postgresql.
DB_ADAPTER=
# The database encoding. For DB_ADAPTER values postresql and mysql2,
# this parameter defaults to unicode and utf8 respectively.
DB_ENCODING=
# The database server hostname. Defaults to localhost.
DB_HOST=
# The database server port. Defaults to 3306 for mysql and 5432 for postgresql.
DB_PORT=
# The database database name. Defaults to gitlabhq_production
DB_NAME=
# The database database user. Defaults to root
DB_USER=
# The database database password. Defaults to no password
DB_PASS=
# The database database connection pool count. Defaults to 10.
DB_POOL=

# Enable mail delivery via SMTP. Defaults to true if SMTP_USER is defined, else defaults to false.
SMTP_ENABLED=
# SMTP domain. Defaults towww.gmail.com
SMTP_DOMAIN=
# SMTP server host. Defaults to smtp.gmail.com.
SMTP_HOST=
# SMTP server port. Defaults to 587.
SMTP_PORT=
# SMTP username.
SMTP_USER=
# SMTP password.
SMTP_PASS=
# Enable STARTTLS. Defaults to true.
SMTP_STARTTLS=
# Enable SSL/TLS. Defaults to false.
SMTP_TLS=
# SMTP openssl verification mode. Accepted values are none, peer, client_once and fail_if_no_peer_cert.
# Defaults to none.
SMTP_OPENSSL_VERIFY_MODE=
# Specify the SMTP authentication method. Defaults to login if SMTP_USER is set.
SMTP_AUTHENTICATION=
# Enable custom CA certificates for SMTP email configuration. Defaults to false.
SMTP_CA_ENABLED=
# Specify the ca_path parameter for SMTP email configuration. Defaults to /home/git/data/certs.
SMTP_CA_PATH=
# Specify the ca_file parameter for SMTP email configuration. Defaults to /home/git/data/certs/ca.crt.
SMTP_CA_FILE=

# Enable mail delivery via IMAP. Defaults to true if IMAP_USER is defined, else defaults to false.
IMAP_ENABLED=
# IMAP server host. Defaults to imap.gmail.com.
IMAP_HOST=
# IMAP server port. Defaults to 993.
IMAP_PORT=
# IMAP username.
IMAP_USER=
# IMAP password.
IMAP_PASS=
# Enable SSL. Defaults to true.
IMAP_SSL=
# Enable STARTSSL. Defaults to false.
IMAP_STARTTLS=
# The name of the mailbox where incoming mail will end up. Defaults to inbox.
IMAP_MAILBOX=

# Enable LDAP. Defaults to false
LDAP_ENABLED=
# Label to show on login tab for LDAP server. Defaults to 'LDAP'
LDAP_LABEL=
# LDAP Host
LDAP_HOST=
# LDAP Port. Defaults to 389
LDAP_PORT=
# LDAP UID. Defaults to sAMAccountName
LDAP_UID=
# LDAP method, Possible values are ssl, tls and plain. Defaults to plain
LDAP_METHOD=
# No default.
LDAP_BIND_DN=
# LDAP password
LDAP_PASS=
# Timeout, in seconds, for LDAP queries. Defaults to 10.
LDAP_TIMEOUT=
# Specifies if LDAP server is Active Directory LDAP server. If your LDAP server is not AD, set this to false.
# Defaults to true,
LDAP_ACTIVE_DIRECTORY=
# If enabled, GitLab will ignore everything after the first '@' in the LDAP username submitted by the user on login.
# Defaults to false if LDAP_UID is userPrincipalName, else true.
LDAP_ALLOW_USERNAME_OR_EMAIL_LOGIN=
# Locks down those users until they have been cleared by the admin. Defaults to false.
LDAP_BLOCK_AUTO_CREATED_USERS=
# Base where we can search for users. No default.
LDAP_BASE=
# Filter LDAP users. No default.
LDAP_USER_FILTER=

# Enable OAuth support. Defaults to true if any of the support OAuth providers is configured, else defaults to false.
OAUTH_ENABLED=
# Automatically sign in with a specific OAuth provider without showing GitLab sign-in page. Accepted values are cas3,
# github, bitbucket, gitlab, google_oauth2, facebook, twitter, saml, crowd, auth0 and azure_oauth2. No default.
OAUTH_AUTO_SIGN_IN_WITH_PROVIDER=
# Comma separated list of oauth providers for single sign-on. This allows users to login without having a user account.
# The account is created automatically when authentication is successful. Accepted values are cas3, github, bitbucket,
# gitlab, google_oauth2, facebook, twitter, saml, crowd, auth0 and azure_oauth2. No default.
OAUTH_ALLOW_SSO=
# Locks down those users until they have been cleared by the admin. Defaults to true.
OAUTH_BLOCK_AUTO_CREATED_USERS=
# Look up new users in LDAP servers. If a match is found (same uid), automatically link the omniauth identity with the
# LDAP account. Defaults to false.
OAUTH_AUTO_LINK_LDAP_USER=
# Allow users with existing accounts to login and auto link their account via SAML login, without having to do a manual
# login first and manually add SAML. Defaults to false.
OAUTH_AUTO_LINK_SAML_USER=
# Comma separated list if oauth providers to disallow access to internal projects. Users creating accounts via these
# providers will have access internal projects. Accepted values are cas3, github, bitbucket, gitlab, google_oauth2,
# facebook, twitter, saml, crowd, auth0 and azure_oauth2. No default.
OAUTH_EXTERNAL_PROVIDERS=

# The "Sign in with" button label. Defaults to "cas3".
OAUTH_CAS3_LABEL=
# CAS3 server URL. No defaults.
OAUTH_CAS3_SERVER=
# Disable CAS3 SSL verification. Defaults to false.
OAUTH_CAS3_DISABLE_SSL_VERIFICATION=
# CAS3 login URL. Defaults to /cas/login
OAUTH_CAS3_LOGIN_URL=
# CAS3 validation URL. Defaults to /cas/p3/serviceValidate
OAUTH_CAS3_VALIDATE_URL=
# CAS3 logout URL. Defaults to /cas/logout
OAUTH_CAS3_LOGOUT_URL=

# Google App Client ID. No defaults.
OAUTH_GOOGLE_API_KEY=
# Google App Client Secret. No defaults.
OAUTH_GOOGLE_APP_SECRET=
# List of Google App restricted domains. Value is comma separated list of single quoted groups.
# Example: 'exemple.com','exemple2.com'. No defaults.
OAUTH_GOOGLE_RESTRICT_DOMAIN=

# Facebook App API key. No defaults.
OAUTH_FACEBOOK_API_KEY=
# Facebook App API secret. No defaults.
OAUTH_FACEBOOK_APP_SECRET=

# Twitter App API key. No defaults.
OAUTH_TWITTER_API_KEY=
# Twitter App API secret. No defaults.
OAUTH_TWITTER_APP_SECRET=

# authentiq Client ID. No defaults.
OAUTH_AUTHENTIQ_CLIENT_ID=
# authentiq Client secret. No defaults.
OAUTH_AUTHENTIQ_CLIENT_SECRET=
# Scope of Authentiq Application Defaults to 'aq:name email~rs address aq:push'
OAUTH_AUTHENTIQ_SCOPE=
# Callback URL for Authentiq. No defaults.
OAUTH_AUTHENTIQ_REDIRECT_URI=

# GitHub App Client ID. No defaults.
OAUTH_GITHUB_API_KEY=
# GitHub App Client secret. No defaults.
OAUTH_GITHUB_APP_SECRET=
# Url to the GitHub Enterprise server. Defaults to https://github.com
OAUTH_GITHUB_URL=
# Enable SSL verification while communicating with the GitHub server. Defaults to true.
OAUTH_GITHUB_VERIFY_SSL=

# GitLab App Client ID. No defaults.
OAUTH_GITLAB_API_KEY=
# GitLab App Client secret. No defaults.
OAUTH_GITLAB_APP_SECRET=

# BitBucket App Client ID. No defaults.
OAUTH_BITBUCKET_API_KEY=
# BitBucket App Client secret. No defaults.
OAUTH_BITBUCKET_APP_SECRET=

# The URL at which the SAML assertion should be received. When GITLAB_HTTPS=true, defaults to
# https://${GITLAB_HOST}/users/auth/saml/callback else defaults to http://${GITLAB_HOST}/users/auth/saml/callback.
OAUTH_SAML_ASSERTION_CONSUMER_SERVICE_URL=
# The SHA1 fingerprint of the certificate. No Defaults.
OAUTH_SAML_IDP_CERT_FINGERPRINT=
# The URL to which the authentication request should be sent. No defaults.
OAUTH_SAML_IDP_SSO_TARGET_URL=
# The name of your application. When GITLAB_HTTPS=true, defaults to https://${GITLAB_HOST} else defaults to
# http://${GITLAB_HOST}.
OAUTH_SAML_ISSUER=
# The "Sign in with" button label. Defaults to "Our SAML Provider".
OAUTH_SAML_LABEL=
# Describes the format of the username required by GitLab,
# Defaults to urn:oasis:names:tc:SAML:2.0:nameid-format:transient
OAUTH_SAML_NAME_IDENTIFIER_FORMAT=
# Map groups attribute in a SAMLResponse to external groups. No defaults.
OAUTH_SAML_GROUPS_ATTRIBUTE=
# List of external groups in a SAMLResponse. Value is comma separated list of single quoted groups.
# Example: 'group1','group2'. No defaults.
OAUTH_SAML_EXTERNAL_GROUPS=
# Map 'email' attribute name in a SAMLResponse to entries in the OmniAuth info hash, No defaults.
# See GitLab documentation for more details.
OAUTH_SAML_ATTRIBUTE_STATEMENTS_EMAIL=
# Map 'name' attribute in a SAMLResponse to entries in the OmniAuth info hash, No defaults.
# See GitLab documentation for more details.
OAUTH_SAML_ATTRIBUTE_STATEMENTS_NAME=
# Map 'first_name' attribute in a SAMLResponse to entries in the OmniAuth info hash, No defaults.
# See GitLab documentation for more details.
OAUTH_SAML_ATTRIBUTE_STATEMENTS_FIRST_NAME=
# Map 'last_name' attribute in a SAMLResponse to entries in the OmniAuth info hash, No defaults.
# See GitLab documentation for more details.
OAUTH_SAML_ATTRIBUTE_STATEMENTS_LAST_NAME=

# Crowd server url. No defaults.
OAUTH_CROWD_SERVER_URL=
# Crowd server application name. No defaults.
OAUTH_CROWD_APP_NAME=
# Crowd server application password. No defaults.
OAUTH_CROWD_APP_PASSWORD=

# Auth0 Client ID. No defaults.
OAUTH_AUTH0_CLIENT_ID=
# Auth0 Client secret. No defaults.
OAUTH_AUTH0_CLIENT_SECRET=
# Auth0 Domain. No defaults.
OAUTH_AUTH0_DOMAIN=

# Azure Client ID. No defaults.
OAUTH_AZURE_API_KEY=
# Azure Client secret. No defaults.
OAUTH_AZURE_API_SECRET=
# Azure Tenant ID. No defaults.
OAUTH_AZURE_TENANT_ID=

# Enables gravatar integration. Defaults to true.
GITLAB_GRAVATAR_ENABLED=
# Sets a custom gravatar url. Defaults to http://www.gravatar.com/avatar/%{hash}?s=%{size}&d=identicon.
# This can be used for Libravatar integration.
GITLAB_GRAVATAR_HTTP_URL=
# Same as above, but for https. Defaults to https://secure.gravatar.com/avatar/%{hash}?s=%{size}&d=identicon.
GITLAB_GRAVATAR_HTTPS_URL=

# Sets the uid for user git to the specified uid. Defaults to 1000.
USERMAP_UID=
# Sets the gid for group git to the specified gid. Defaults to USERMAP_UID if defined, else defaults to 1000.
USERMAP_GID=

# Google Analytics ID. No defaults.
GOOGLE_ANALYTICS_ID=

# Sets the Piwik URL. No defaults.
PIWIK_URL=
# Sets the Piwik site ID. No defaults.
PIWIK_SITE_ID=

# Enables automatic uploads to an Amazon S3 instance. Defaults to false.
AWS_BACKUPS=
# AWS region. No defaults.
AWS_BACKUP_REGION=
# AWS access key id. No defaults.
AWS_BACKUP_ACCESS_KEY_ID=
# AWS secret access key. No defaults.
AWS_BACKUP_SECRET_ACCESS_KEY=
# AWS bucket for backup uploads. No defaults.
AWS_BACKUP_BUCKET=
# Enables mulitpart uploads when file size reaches a defined size. See at AWS S3 Docs
AWS_BACKUP_MULTIPART_CHUNK_SIZE=

# Location of custom robots.txt. Uses GitLab's default robots.txt configuration by default.
# See www.robotstxt.org for examples.
GITLAB_ROBOTS_PATH=

# Enable/disable rack middleware for blocking & throttling abusive requests Defaults to true.
RACK_ATTACK_ENABLED=
# Always allow requests from whitelisted host. Defaults to 127.0.0.1
RACK_ATTACK_WHITELIST=
# Number of failed auth attempts before which an IP should be banned. Defaults to 10
RACK_ATTACK_MAXRETRY=
# Number of seconds before resetting the per IP auth attempt counter. Defaults to 60.
RACK_ATTACK_FINDTIME=
# Number of seconds an IP should be banned after too many auth attempts. Defaults to 3600.
RACK_ATTACK_BANTIME=

# Timeout for gitlab workhorse http proxy. Defaults to 5m0s.
GITLAB_WORKHORSE_TIMEOUT=

