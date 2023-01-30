rule Potential_cryptographic_private_key {
    meta:
        description = "Potential cryptographic private key"
    strings:
        $extension = ".pem"
    condition:
        $extension
}

rule Log_file {
    meta:
        description = "Log file"
    strings:
        $extension = ".log"
    condition:
        $extension
}

rule Potential_cryptographic_key_bundle {
    meta:
        description = "Potential cryptographic key bundle"
    strings:
        $extension = ".pkcs12"
    condition:
        $extension
}

rule Potential_cryptographic_key_bundle2 {
    meta:
        description = "Potential cryptographic key bundle"
    strings:
        $extension = ".p12"
    condition:
        $extension
}

rule Potential_cryptographic_key_bundle3 {
    meta:
        description = "Potential cryptographic key bundle"
    strings:
        $extension = ".pfx"
    condition:
        $extension
}

rule Potential_cryptographic_key_bundle4 {
    meta:
        description = "Potential cryptographic key bundle"
    strings:
        $extension = ".asc"
    condition:
        $extension
}

rule Pidgin_OTR_private_key {
    meta:
        description = "Pidgin OTR private key"
    strings:
        $filename = "otr.private_key"
    condition:
        $filename
}

rule OpenVPN_client_configuration_file {
    meta:
        description = "OpenVPN client configuration file"
    strings:
        $extension = ".ovpn"
    condition:
        $extension
}

rule Azure_service_configuration_schema_file {
    meta:
        description = "Azure service configuration schema file"
    strings:
        $extension = ".cscfg"
    condition:
        $extension
}

rule Remote_Desktop_connection_file {
    meta:
        description = "Remote Desktop connection file"
    strings:
        $extension = ".rdp"
    condition:
        $extension
}



rule Microsoft_SQL_database_file
{
    meta:
        description = "Microsoft SQL database file"
    strings:
        $mdf_extension = ".mdf"
    condition:
        $mdf_extension in (extension)
}

rule Microsoft_SQL_server_compact_database_file
{
    meta:
        description = "Microsoft SQL server compact database file"
    strings:
        $sdf_extension = ".sdf"
    condition:
        $sdf_extension in (extension)
}

rule SQLite_database_file
{
    meta:
        description = "SQLite database file"
    strings:
        $sqlite_extension = ".sqlite"
    condition:
        $sqlite_extension in (extension)
}

rule SQLite3_database_file
{
    meta:
        description = "SQLite3 database file"
    strings:
        $sqlite3_extension = ".sqlite3"
    condition:
        $sqlite3_extension in (extension)
}

rule Microsoft_BitLocker_recovery_key_file
{
    meta:
        description = "Microsoft BitLocker recovery key file"
    strings:
        $bek_extension = ".bek"
    condition:
        $bek_extension in (extension)
}

rule Microsoft_BitLocker_Trusted_Platform_Module_password_file
{
    meta:
        description = "Microsoft BitLocker Trusted Platform Module password file"
    strings:
        $tpm_extension = ".tpm"
    condition:
        $tpm_extension in (extension)
}

rule Windows_BitLocker_full_volume_encrypted_data_file
{
    meta:
        description = "Windows BitLocker full volume encrypted data file"
    strings:
        $fve_extension = ".fve"
    condition:
        $fve_extension in (extension)
}

rule Java_keystore_file
{
    meta:
        description = "Java keystore file"
    strings:
        $jks_extension = ".jks"
    condition:
        $jks_extension in (extension)
}

rule Password_Safe_database_file
{
    meta:
        description = "Password Safe database file"
    strings:
        $psafe3_extension = ".psafe3"
    condition:
        $psafe3_extension in (extension)
}

rule Ruby_On_Rails_secret_token_configuration_file
{
    meta:
        description = "Ruby On Rails secret token configuration file"
    strings:
        $secret_token_filename = "secret_token.rb"
    condition:
        $secret_token_filename in (filename)
}

rule Carrierwave_configuration_file
{
    meta:
        description = "Carrierwave configuration file"
    strings:
        $carrierwave_filename = "carrierwave.rb"
    condition:
        $carrierwave_filename in (filename)
}


rule Potential_Ruby_On_Rails_database_configuration_file {
  strings:
    $f = "database.yml"
  condition:
    $f
}

rule OmniAuth_configuration_file {
  strings:
    $f = "omniauth.rb"
  condition:
    $f
}

rule Django_configuration_file {
  strings:
    $f = "settings.py"
  condition:
    $f
}

rule 1Password_password_manager_database_file {
  strings:
    $e = ".agilekeychain"
  condition:
    $e
}

rule Apple_Keychain_database_file {
  strings:
    $e = ".keychain"
  condition:
    $e
}

rule Network_traffic_capture_file {
  strings:
    $e = ".pcap"
  condition:
    $e
}

rule GnuCash_database_file {
  strings:
    $e = ".gnucash"
  condition:
    $e
}

rule Jenkins_publish_over_ssh_plugin_file {
  strings:
    $f = "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml"
  condition:
    $f
}

rule Potential_Jenkins_credentials_file {
  strings:
    $f = "credentials.xml"
  condition:
    $f
}

rule KDE_Wallet_Manager_database_file {
  strings:
    $e = ".kwallet"
  condition:
    $e
}

rule Potential_MediaWiki_configuration_file {
  strings:
    $f = "LocalSettings.php"
  condition:
    $f
}

rule Tunnelblick_VPN_configuration_file {
  strings:
    $e = ".tblk"
  condition:
    $e
}

rule Sequel_Pro_MySQL_database_manager_bookmark_file {
  strings:
    $f = "Favorites.plist"
  condition:
    $f
}

rule Little_Snitch_firewall_configuration_file {
  strings:
    $f = "configuration.user.xpl"
  condition:
    $f
}

rule Day_One_journal_file {
  strings:
    $e = ".dayone"
  condition:
    $e
}

rule Potential_jrnl_journal_file {
  strings:
    $f = "journal.txt"
  condition:
    $f
}

rule Chef_Knife_configuration_file {
  strings:
    $f = "knife.rb"
  condition:
    $f
}

rule cPanel_backup_ProFTPd_credentials_file {
  strings:
    $f = "proftpdpasswd"
  condition:
    $f
}

rule Robomongo_MongoDB_manager_configuration_file {
  strings:
    $f = "robomongo.json"
  condition:
    $f
}

rule FileZilla_FTP_config_file {
meta:
description = "FileZilla FTP configuration file"
strings:
$file = "filezilla.xml"
condition:
$file
}

rule FileZilla_FTP_recent_servers_file {
meta:
description = "FileZilla FTP recent servers file"
strings:
$file = "recentservers.xml"
condition:
$file
}

rule Ventrilo_server_config_file {
meta:
description = "Ventrilo server configuration file"
strings:
$file = "ventrilo_srv.ini"
condition:
$file
}

rule Terraform_variable_config_file {
meta:
description = "Terraform variable config file"
strings:
$file = "terraform.tfvars"
condition:
$file
}

rule Shell_config_file {
meta:
description = "Shell configuration file"
strings:
$file1 = ".exports"
$file2 = ".functions"
$file3 = ".extra"
condition:
$file1 or $file2 or $file3
}

rule Private_SSH_key_rsa {
meta:
description = "Private SSH key (rsa)"
strings:
$file = /^.*_rsa$/
condition:
$file
}

rule Private_SSH_key_dsa {
meta:
description = "Private SSH key (dsa)"
strings:
$file = /^.*_dsa$/
condition:
$file
}

rule Private_SSH_key_ed25519 {
meta:
description = "Private SSH key (ed25519)"
strings:
$file = /^.*_ed25519$/
condition:
$file
}

rule Private_SSH_key_ecdsa {
meta:
description = "Private SSH key (ecdsa)"
strings:
$file = /^.*_ecdsa$/
condition:
$file
}

rule SSH_config_file {
meta:
description = "SSH configuration file"
strings:
$path = /.?ssh/config$/
condition:
$path
}

rule Potential_cryptographic_private_key {
meta:
description = "Potential cryptographic private key"
strings:
$extension = /^key(pair)?$/
condition:
$extension
}

rule Shell_command_history_file {
meta:
description = "Shell command history file"
strings:
$file = /^.?(bash_|zsh_|sh_|z)?history$/
condition:
$file
}

rule MySQL_client_command_history_file {
meta:
description = "MySQL client command history file"
strings:
$file = /^.?mysql_history$/
condition:
$file
}


rule Shell_command_history {
meta:
description = "Shell command history file"
strings:
$regex = /^.?(bash_|zsh_|sh_|z)?history$/
condition:
$regex
}

rule MySQL_client_history {
meta:
description = "MySQL client command history file"
strings:
$regex = /^.?mysql_history$/
condition:
$regex
}

rule PostgreSQL_client_history {
meta:
description = "PostgreSQL client command history file"
strings:
$regex = /^.?psql_history$/
condition:
$regex
}

rule PostgreSQL_password_file {
meta:
description = "PostgreSQL password file"
strings:
$regex = /^.?pgpass$/
condition:
$regex
}

rule Ruby_IRB_console_history {
meta:
description = "Ruby IRB console history file"
strings:
$regex = /^.?irb_history$/
condition:
$regex
}

rule Pidgin_chat_config {
meta:
description = "Pidgin chat client account configuration file"
strings:
$regex = /.?purple/accounts.xml$/
condition:
$regex
}

rule Hexchat_XChat_server_list {
meta:
description = "Hexchat/XChat IRC client server list configuration file"
strings:
$regex = /.?xchat2?
condition:
$regex
}


rule FileZilla_FTP_configuration_file {
  meta:
    description = "FileZilla FTP configuration file"
  strings:
    $filezilla = "filezilla.xml"
  condition:
    $filezilla
}

rule FileZilla_FTP_recent_servers_file {
  meta:
    description = "FileZilla FTP recent servers file"
  strings:
    $recentservers = "recentservers.xml"
  condition:
    $recentservers
}

rule Ventrilo_server_configuration_file {
  meta:
    description = "Ventrilo server configuration file"
  strings:
    $ventrilo = "ventrilo_srv.ini"
  condition:
    $ventrilo
}

rule Terraform_variable_config_file {
  meta:
    description = "Terraform variable config file"
  strings:
    $terraform = "terraform.tfvars"
  condition:
    $terraform
}

rule Shell_configuration_file_exports {
  meta:
    description = "Shell configuration file"
  strings:
    $exports = ".exports"
  condition:
    $exports
}

rule Shell_configuration_file_functions {
  meta:
    description = "Shell configuration file"
  strings:
    $functions = ".functions"
  condition:
    $functions
}

rule Shell_configuration_file_extra {
  meta:
    description = "Shell configuration file"
  strings:
    $extra = ".extra"
  condition:
    $extra
}

rule Private_SSH_key_rsa {
  meta:
    description = "Private SSH key"
  strings:
    $rsa = /^.*_rsa$/
  condition:
    $rsa
}

rule Private_SSH_key_dsa {
  meta:
    description = "Private SSH key"
  strings:
    $dsa = /^.*_dsa$/
  condition:
    $dsa
}

rule Private_SSH_key_ed25519 {
  meta:
    description = "Private SSH key"
  strings:
    $ed25519 = /^.*_ed25519$/
  condition:
    $ed25519
}

rule Private_SSH_key_ecdsa {
  meta:
    description = "Private SSH key"
  strings:
    $ecdsa = /^.*_ecdsa$/
  condition:
    $ecdsa
}

rule SSH_configuration_file {
  meta:
    description = "SSH configuration file"
  strings:
    $ssh_config = /\.?ssh\/config$/
  condition:
    $ssh_config
}

rule Potential_cryptographic_private_key {
  meta:
    description = "Potential cryptographic private key"
  strings:
    $key = /^key(pair)?$/
  condition:
    $key
}

rule Shell_command_history_file {
    meta:
        description = "Shell command history file"
    strings:
        $history = "history"
    condition:
        all of them
        (
            $history in (filename) and
            (
                filename =~ /^\.(bash_|zsh_|sh_|z)?history$/ or
                filename =~ /^(bash_|zsh_|sh_|z)?history$/
            )
        )
}

rule MySQL_client_command_history_file {
    meta:
        description = "MySQL client command history file"
    strings:
        $mysql_history = "mysql_history"
    condition:
        all of them
        (
            $mysql_history in (filename) and
            (
                filename =~ /^\.(mysql_history)$/ or
                filename =~ /^(mysql_history)$/
            )
        )
}

rule PostgreSQL_client_command_history_file {
    meta:
        description = "PostgreSQL client command history file"
    strings:
        $psql_history = "psql_history"
    condition:
        all of them
        (
            $psql_history in (filename) and
            (
                filename =~ /^\.(psql_history)$/ or
                filename =~ /^(psql_history)$/
            )
        )
}

rule PostgreSQL_password_file {
    meta:
        description = "PostgreSQL password file"
    strings:
        $pgpass = "pgpass"
    condition:
        all of them
        (
            $pgpass in (filename) and
            (
                filename =~ /^\.(pgpass)$/ or
                filename =~ /^(pgpass)$/
            )
        )
}

rule Ruby_IRB_console_history_file {
    meta:
        description = "Ruby IRB console history file"
    strings:
        $irb_history = "irb_history"
    condition:
        all of them
        (
            $irb_history in (filename) and
            (
                filename =~ /^\.(irb_history)$/ or
                filename =~ /^(irb_history)$/
            )
        )
}



rule Pidgin_chat_client_account_configuration_file {
meta:
description = "Pidgin chat client account configuration file"
strings:
$accounts_xml = "purple/accounts.xml"
condition:
$accounts_xml in (path)
}

rule Hexchat_XChat_IRC_client_server_list_configuration_file {
meta:
description = "Hexchat/XChat IRC client server list configuration file"
strings:
$servlist_conf = "xchat2/servlist.conf"
$servlist__conf = "xchat/servlist_.conf"
condition:
$servlist_conf in (path) or $servlist__conf in (path)
}

rule Irssi_IRC_client_configuration_file {
meta:
description = "Irssi IRC client configuration file"
strings:
$irssi_config = "irssi/config"
condition:
$irssi_config in (path)
}

rule Recon_ng_web_reconnaissance_framework_API_key_database {
meta:
description = "Recon-ng web reconnaissance framework API key database"
strings:
$keys_db = "recon-ng/keys.db"
condition:
$keys_db in (path)
}

rule DBeaver_SQL_database_manager_configuration_file {
meta:
description = "DBeaver SQL database manager configuration file"
strings:
$dbeaver_data_sources_xml = "dbeaver-data-sources.xml"
condition:
$dbeaver_data_sources_xml in (filename)
}


rule Mutt_e-mail_client_configuration_file
{
    meta:
        description = "Mutt e-mail client configuration file"
    strings:
        $muttrc_filename = ".muttrc"
    condition:
        $muttrc_filename in (filename)
}

rule S3cmd_configuration_file
{
    meta:
        description = "S3cmd configuration file"
    strings:
        $s3cfg_filename = ".s3cfg"
    condition:
        $s3cfg_filename in (filename)
}

rule AWS_CLI_credentials_file
{
    meta:
        description = "AWS CLI credentials file"
    strings:
        $credentials_path = ".aws/credentials"
    condition:
        $credentials_path in (path)
}

rule SFTP_connection_configuration_file
{
    meta:
        description = "SFTP connection configuration file"
    strings:
        $sftp_config_filename = "sftp-config"
        $sftp_config_filename_json = "sftp-config.json"
    condition:
        $sftp_config_filename in (filename) or $sftp_config_filename_json in (filename)
}

rule T_command_line_Twitter_client_configuration_file
{
    meta:
        description = "T command-line Twitter client configuration file"
    strings:
        $trc_filename = ".trc"
    condition:
        $trc_filename in (filename)
}

rule Shell_configuration_file
{
    meta:
        description = "Shell configuration file"
    strings:
        $bashrc_filename = ".bashrc"
        $zshrc_filename = ".zshrc"
        $cshrc_filename = ".cshrc"
    condition:
        $bashrc_filename in (filename) or $zshrc_filename in (filename) or $cshrc_filename in (filename)
}

rule Shell_profile_configuration_file {
meta:
description = "Shell profile configuration file"
strings:
$filename = /^.?(bash_|zsh_)?profile$/
condition:
$filename
}

rule Shell_command_alias_configuration_file {
meta:
description = "Shell command alias configuration file"
strings:
$filename = /^.?(bash_|zsh_)?aliases$/
condition:
$filename
}

rule PHP_configuration_file {
meta:
description = "PHP configuration file"
strings:
$filename = /config(.inc)?.php$/
condition:
$filename
}

rule Private_GNOME_Keyring {
meta:
description = "GNOME Keyring database file"
strings:
$keyring = /^key(store|ring)$/
condition:
$keyring
}

rule Private_KeePass_database {
meta:
description = "KeePass password manager database file"
strings:
$keypass = /^kdbx?$/
condition:
$keypass
}

rule SQL_dump {
meta:
description = "SQL dump file"
strings:
$sqldump = /^sql(dump)?$/
condition:
$sqldump
}

rule Apache_htpasswd {
meta:
description = "Apache htpasswd file"
strings:
$htpasswd = /^.?htpasswd$/
condition:
$htpasswd
}

rule Auto_Login_Config {
meta:
description = "Configuration file for auto-login process"
strings:
$netrc = /^(.|_)?netrc$/
condition:
$netrc
}

rule Rubygems_Credentials {
meta:
description = "Rubygems credentials file"
strings:
$gemcreds = /.?gem/credentials$/
condition:
$gemcreds
}

rule Tugboat_Configuration {
meta:
description = "Tugboat DigitalOcean management tool configuration"
strings:
$tugboat = /^.?tugboat$/
condition:
$tugboat
}

rule Doctl_Configuration {
meta:
description = "DigitalOcean doctl command-line client configuration file"
strings:
$doctl = /doctl/config.yaml$/
condition:
$doctl
}

rule Git_Credentials_Store {
meta:
description = "git-credential-store helper credentials file"
strings:
$gitcreds = /^.?git-credentials$/
condition:
$gitcreds
}


rule GitHub_Hub_command_line_client_configuration_file {
  meta:
    description = "GitHub Hub command-line client configuration file"
  strings:
    $path = /config/hub$/
  condition:
    $path
}

rule Git_configuration_file {
  meta:
    description = "Git configuration file"
  strings:
    $filename = /^\.?gitconfig$/
  condition:
    $filename
}

rule Chef_private_key {
  meta:
    description = "Chef private key"
  strings:
    $path = /\.?chef\/(.*)\.pem$/
  condition:
    $path
}

rule Potential_Linux_shadow_file {
  meta:
    description = "Potential Linux shadow file"
  strings:
    $path = /etc/shadow$/
  condition:
    $path
}

rule Potential_Linux_passwd_file {
  meta:
    description = "Potential Linux passwd file"
  strings:
    $path = /etc/passwd$/
  condition:
    $path
}

rule Docker_configuration_file {
  meta:
    description = "Docker configuration file"
  strings:
    $filename = /^\.?dockercfg$/
  condition:
    $filename
}

rule NPM_configuration_file {
  meta:
    description = "NPM configuration file"
  strings:
    $filename = /^\.?npmrc$/
  condition:
    $filename
}

rule Environment_configuration_file {
  meta:
    description = "Environment configuration file"
  strings:
    $filename = /^\.?env$/
  condition:
    $filename
}

rule AWS_Access_Key_ID_Value {
  meta:
    description = "AWS Access Key ID Value"
  strings:
    $contents = /(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/
  condition:
    $contents
}

rule AWS_Access_Key_ID {
  meta:
    description = "AWS Access Key ID"
  strings:
    $contents = /((\"|'|`)?((?i)aws)?_?((?i)access)_?((?i)key)?_?((?i)id)?(\"|'|`)?(\\s{0,50})?(:|=>|=)(\\s{0,50})?(\"|'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\"|'|`)?)/
  condition:
    $contents
}

rule AWS_Account_ID {
strings:
$aws_account_id = (("|'|)?((?i)aws)?_?((?i)account)_?((?i)id)?(\"|'|)?(\s{0,50})?(:|=>|=)(\s{0,50})?("|'|)?[0-9]{4}-?[0-9]{4}-?[0-9]{4}(\"|'|)?)

condition:
$aws_account_id
}

rule AWS_Secret_Access_Key {
strings:
$aws_secret_access_key = (("|'|)?((?i)aws)?_?((?i)secret)_?((?i)access)?_?((?i)key)?_?((?i)id)?(\"|'|)?(\s{0,50})?(:|=>|=)(\s{0,50})?("|'|)?[A-Za-z0-9/+=]{40}(\"|'|)?)

condition:
$aws_secret_access_key
}

rule AWS_Session_Token {
strings:
$aws_session_token = (("|'|)?((?i)aws)?_?((?i)session)?_?((?i)token)?(\"|'|)?(\s{0,50})?(:|=>|=)(\s{0,50})?("|'|)?[A-Za-z0-9/+=]{100,400}(\"|'|)?)

condition:
$aws_session_token
}

rule Artifactory {
strings:
$artifactory = (?i)artifactory.{0,50}("|'|)?[a-zA-Z0-9=]{112}(\"|'|)?

condition:
$artifactory
}

rule CodeClimate {
strings:
$codeclimate = (?i)codeclima.{0,50}("|'|)?[0-9a-f]{64}(\"|'|)?

condition:
$codeclimate
}

rule Facebook_access_token {
strings:
$facebook_access_token = "EAACEdEose0cBA[0-9A-Za-z]+"

condition:
$facebook_access_token
}

rule Google_GCM_Service_account {
strings:
$google_gcm_service_account = (("|'|)?type(\"|'|)?\s{0,50}(:|=>|=)\s{0,50}("|'|)?service_account(\"|'|)?,?)

condition:
$google_gcm_service_account
}


rule Stripe_API_key {
    meta:
        description = "Matches contents with a Stripe API key"
    strings:
        $api_key = /(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}/
    condition:
        $api_key
}

rule Google_OAuth_Key {
    meta:
        description = "Matches contents with a Google OAuth Key"
    strings:
        $oauth_key = /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/
    condition:
        $oauth_key
}

rule Google_Cloud_API_Key {
    meta:
        description = "Matches contents with a Google Cloud API Key"
    strings:
        $api_key = /AIza[0-9A-Za-z\\-_]{35}/
    condition:
        $api_key
}

rule Google_OAuth_Access_Token {
    meta:
        description = "Matches contents with a Google OAuth Access Token"
    strings:
        $access_token = /ya29\\.[0-9A-Za-z\\-_]+/
    condition:
        $access_token
}

rule Picatic_API_key {
    meta:
        description = "Matches contents with a Picatic API key"
    strings:
        $api_key = /sk_[live|test]_[0-9a-z]{32}/
    condition:
        $api_key
}

rule Square_Access_Token {
    meta:
        description = "Matches contents with a Square Access Token"
    strings:
        $access_token = /sq0atp-[0-9A-Za-z\\-_]{22}/
    condition:
        $access_token
}

rule Square_OAuth_Secret {
    meta:
        description = "Matches contents with a Square OAuth Secret"
    strings:
        $oauth_secret = /sq0csp-[0-9A-Za-z\\-_]{43}/
    condition:
        $oauth_secret
}

rule PayPal_Braintree_Access_Token {
    meta:
        description = "Matches contents with a PayPal/Braintree Access Token"
    strings:
        $access_token = /access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}/
    condition:
        $access_token
}


rule SonarQube_Docs_API_Key {
    strings:
        $api_key = /(?i)sonar.{0,50}(\"|'|`)?[0-9a-f]{40}(\"|'|`)?/

    condition:
        $api_key
}

rule HockeyApp {
    strings:
        $api_key = /(?i)hockey.{0,50}(\"|'|`)?[0-9a-f]{32}(\"|'|`)?/

    condition:
        $api_key
}

rule username_and_password_in_URI {
strings:
$uri = /([\w+]{1,24})(://)([^$<]{1})([^\s";]{1,}):([^$<]{1})([^\s";/]{1,})@[-a-zA-Z0-9@:%._+~#=]{1,256}.[a-zA-Z0-9()]{1,24}([^\s]+)/
condition:
$uri
}


rule NuGet_API_Key
{
strings:
$key = /(?i)nuget.{0,50}("|'|)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}("|'|)?/
condition:
$key
}


rule OpenWeather_API_Key {
strings:
$openweather = /(?i)openweather.{0,50}("|'|)?[0-9a-fA-F]{32}("|'|)?/
condition:
$openweather
}


rule StackHawk_API_Key {
strings:
$hawk = "hawk.[0-9A-Za-z-]{20}.[0-9A-Za-z-]"
condition:
$hawk
}

rule Potential_PuTTYgen_private_key {
strings:
$ppk = ".ppk"
condition:
$ppk
}

rule Heroku_config_file {
strings:
$heroku_json = "heroku.json"
condition:
$heroku_json
}

rule SQL_Data_dump_file {
strings:
$sqldump = ".sqldump"
condition:
$sqldump
}

rule MySQL_dump_w_bcrypt_hashes {
strings:
$dump_sql = "dump.sql"
condition:
$dump_sql
}

rule Public_ssh_key {
strings:
$id_rsa_pub = "id_rsa_pub"
condition:
$id_rsa_pub
}

rule Mongoid_config_file {
strings:
$mongoid_yml = "mongoid.yml"
condition:
$mongoid_yml
}

rule Salesforce_credentials_in_a_nodejs_project {
strings:
$salesforce_js = "salesforce.js"
condition:
$salesforce_js
}

rule netrc_with_SMTP_credentials {
strings:
$netrc = ".netrc"
condition:
$netrc
}

rule Created_by_remote_sync_for_Atom {
strings:
$remote_sync_json = ".remote-sync.json"
condition:
$remote_sync_json
}

rule esmtp_configuration {
strings:
$esmtprc = ".esmtprc"
condition:
$esmtprc
}

rule Potential_PuTTYgen_private_key {
  strings:
    $private_key = ".ppk"

  condition:
    $private_key at end of file
}

rule Heroku_config_file {
  strings:
    $heroku_config = "heroku.json"

  condition:
    $heroku_config
}

rule SQL_Data_dump_file {
  strings:
    $sql_dump = ".sqldump"

  condition:
    $sql_dump at end of file
}

rule MySQL_dump_w_bcrypt_hashes {
  strings:
    $mysql_dump = "dump.sql"

  condition:
    $mysql_dump
}

rule Public_ssh_key {
  strings:
    $ssh_key = "id_rsa_pub"

  condition:
    $ssh_key
}

rule Mongoid_config_file {
  strings:
    $mongoid_config = "mongoid.yml"

  condition:
    $mongoid_config
}

rule Salesforce_credentials_in_a_nodejs_project {
  strings:
    $salesforce_credentials = "salesforce.js"

  condition:
    $salesforce_credentials
}

rule netrc_with_SMTP_credentials {
  strings:
    $netrc_credentials = ".netrc"

  condition:
    $netrc_credentials at end of file
}

rule created_by_remote_sync_for_Atom {
  strings:
    $remote_sync_json = /.remote-sync.json$/

  condition:
    $remote_sync_json
}

rule esmtp_configuration {
  strings:
    $esmtp_config = /.esmtprc$/

  condition:
    $esmtp_config
}

rule created_by_sftp_deployment_for_Atom {
  strings:
    $deployment_config = /(^deployment-config.json?$)|(.ftpconfig$)/

  condition:
    $deployment_config
}

rule Contains_a_private_key {
  strings:
    $private_key = /-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY/

  condition:
    $private_key
}

rule StackHawk_API_Key {
  strings:
    $hawk_api_key = /hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]/

  condition:
    $hawk_api_key
}

rule Potential_PuTTYgen_private_key {
  strings:
    $private_key = ".ppk"

  condition:
    $private_key at end of file
}

rule Heroku_config_file {
  strings:
    $heroku_config = "heroku.json"

  condition:
    $heroku_config
}

rule SQL_Data_dump_file {
  strings:
    $sql_dump = ".sqldump"

  condition:
    $sql_dump at end of file
}

rule MySQL_dump_w_bcrypt_hashes {
  strings:
    $mysql_dump = "dump.sql"

  condition:
    $mysql_dump
}

rule Public_ssh_key {
  strings:
    $ssh_key = "id_rsa_pub"

  condition:
    $ssh_key
}

rule Mongoid_config_file {
  strings:
    $mongoid_config = "mongoid.yml"

  condition:
    $mongoid_config
}

rule Salesforce_credentials_in_a_nodejs_project {
  strings:
    $salesforce_credentials = "salesforce.js"

  condition:
    $salesforce_credentials
}

rule netrc_with_SMTP_credentials {
  strings:
    $netrc_credentials = ".netrc"

  condition:
    $netrc_credentials at end of file
}

rule created_by_remote_sync_for_Atom {
  strings:
    $remote_sync_json = /.remote-sync.json$/

  condition:
    $remote_sync_json
}

rule esmtp_configuration {
  strings:
    $esmtp_config = /.esmtprc$/

  condition:
    $esmtp_config
}

rule created_by_sftp_deployment_for_Atom {
  strings:
    $deployment_config = /(^deployment-config.json?$)|(.ftpconfig$)/

  condition:
    $deployment_config
}

rule Contains_a_private_key {
  strings:
    $private_key = /-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY/

  condition:
    $private_key
}


rule StackHawk_API_Key {
  strings:
    $hawk_api_key = /hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]/

  condition:
    $hawk_api_key
}

rule Potential_PuTTYgen_private_key {
  strings:
    $private_key = ".ppk"

  condition:
    $private_key at end of file
}

rule Heroku_config_file {
  strings:
    $heroku_config = "heroku.json"

  condition:
    $heroku_config
}

rule SQL_Data_dump_file {
  strings:
    $sql_dump = ".sqldump"

  condition:
    $sql_dump at end of file
}

rule MySQL_dump_w_bcrypt_hashes {
  strings:
    $mysql_dump = "dump.sql"

  condition:
    $mysql_dump
}

rule Public_ssh_key {
  strings:
    $ssh_key = "id_rsa_pub"

  condition:
    $ssh_key
}

rule Mongoid_config_file {
  strings:
    $mongoid_config = "mongoid.yml"

  condition:
    $mongoid_config
}

rule Salesforce_credentials_in_a_nodejs_project {
  strings:
    $salesforce_credentials = "salesforce.js"

  condition:
    $salesforce_credentials
}

rule netrc_with_SMTP_credentials {
  strings:
    $netrc_credentials = ".netrc"

  condition:
    $netrc_credentials at end of file
}

rule created_by_remote_sync_for_Atom {
  strings:
    $remote_sync_json = /.remote-sync.json$/

  condition:
    $remote_sync_json
}

rule esmtp_configuration {
  strings:
    $esmtp_config = /.esmtprc$/

  condition:
    $esmtp_config
}

rule created_by_sftp_deployment_for_Atom {
  strings:
    $deployment_config = /(^deployment-config.json?$)|(.ftpconfig$)/

  condition:
    $deployment_config
}

rule Contains_a_private_key {
  strings:
    $private_key = /-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY/

  condition:
    $private_key
}

rule WP_Config {
meta:
description = "WordPress configuration file"
strings:
$wp_config = /define(.{0,20}?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|"].{10,120}['|"]/
condition:
$wp_config
}

rule AWS_Cred_File_Info {
meta:
description = "AWS credentials file information"
strings:
$aws_creds = /(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z/+]{20,40}/
condition:
$aws_creds
}

rule Facebook_Secret_Key {
meta:
description = "Facebook secret key"
strings:
$fb_secret_key = /(?i)(facebook|fb)(.{0,20})?(?-i)['"][0-9a-f]{32}['"]/
condition:
$fb_secret_key
}

rule Facebook_Client_ID {
meta:
description = "Facebook client ID"
strings:
$fb_client_id = /(?i)(facebook|fb)(.{0,20})?['"][0-9]{13,17}['"]/
condition:
$fb_client_id
}

rule Twitter_Secret_Key {
meta:
description = "Twitter secret key"
strings:
$twitter_secret_key = /(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}['"]/
condition:
$twitter_secret_key
}

rule Twitter_Client_ID {
meta:
description = "Twitter client ID"
strings:
$twitter_client_id = /(?i)twitter(.{0,20})?['"][0-9a-z]{18,25}['"]/
condition:
$twitter_client_id
}

rule Github_Key {
meta:
description = "Github key"
strings:
$github_key = /(?i)github(.{0,20})?(?-i)['"][0-9a-zA-Z]{35,40}['"]/
condition:
$github_key
}


rule Heroku_config_file {
    meta:
        description = "Heroku config file"
    strings:
        $file_name = "heroku.json"
    condition:
        $file_name in (0 .. 65535)
}


rule SQL_Data_dump_file {
    meta:
        description = "SQL Data dump file"
    strings:
        $file_extension = ".sqldump"
    condition:
        filesize > 0 and extension($file_extension)
}


rule MySQL_dump_w_bcrypt_hashes {
    meta:
        description = "MySQL dump w/ bcrypt hashes"
    strings:
        $file_name = "dump.sql"
    condition:
        $file_name in (0 .. 65535)
}

rule Public_ssh_key {
    meta:
        description = "Public ssh key"
    strings:
        $file_name = "id_rsa_pub"
    condition:
        $file_name in (0 .. 65535)
}




rule Heroku_config_file {
  meta:
    description = "Heroku config file"
  strings:
    $file = "heroku.json"
  condition:
    $file
}

rule SQL_Data_dump_file {
  meta:
    description = "SQL Data dump file"
  strings:
    $ext = ".sqldump"
  condition:
    ($ext in (pe.resources * 2))
}

rule MySQL_dump_w_bcrypt_hashes {
  meta:
    description = "MySQL dump w/ bcrypt hashes"
  strings:
    $file = "dump.sql"
  condition:
    $file
}

rule Public_ssh_key {
  meta:
    description = "Public ssh key"
  strings:
    $file = "id_rsa_pub"
  condition:
    $file
}

rule Mongoid_config_file {
  meta:
    description = "Mongoid config file"
  strings:
    $file = "mongoid.yml"
  condition:
    $file
}

rule Salesforce_credentials_in_a_nodejs_project {
  meta:
    description = "Salesforce credentials in a nodejs project"
  strings:
    $file = "salesforce.js"
  condition:
    $file
}

rule netrc_with_SMTP_credentials {
  meta:
    description = "netrc with SMTP credentials"
  strings:
    $ext = ".netrc"
  condition:
    ($ext in (pe.resources * 2))
}

rule Created_by_remote_sync_for_Atom {
  meta:
    description = "Created by remote-sync for Atom, contains FTP and/or SCP/SFTP/SSH server details and credentials"
  strings:
    $file = /\.remote-sync.json$/
  condition:
    $file
}

rule esmtp_configuration {
  meta:
    description = "esmtp configuration"
  strings:
    $file = /\.esmtprc$/
  condition:
    $file
}

rule Created_by_sftp_deployment_for_Atom {
  meta:
    description = "Created by sftp-deployment for Atom, contains server details and credentials"
  strings:
    $file = /(^deployment-config.json?$)|(\.ftpconfig$)/
  condition:
    $file
}


rule Contains_private_key {
meta:
description = "Contains a private key"
strings:
$private_key = "-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY"
condition:
$private_key
}

rule WP_Config {
meta:
description = "WordPress Config file"
strings:
$wp_config = "define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|"].{10,120}['|"]"
condition:
$wp_config
}

rule AWS_cred_file_info {
meta:
description = "AWS credentials file"
strings:
$aws_creds = "(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z/+]{20,40}"
condition:
$aws_creds
}

rule Facebook_Secret_Key {
meta:
description = "Facebook secret key"
strings:
$fb_secret = "(?i)(facebook|fb)(.{0,20})?(?-i)['"][0-9a-f]{32}['"]"
condition:
$fb_secret
}

rule Facebook_Client_ID {
meta:
description = "Facebook client ID"
strings:
$fb_client = "(?i)(facebook|fb)(.{0,20})?['"][0-9]{13,17}['"]"
condition:
$fb_client
}

rule Twitter_Secret_Key {
meta:
description = "Twitter secret key"
strings:
$tw_secret = "(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}['"]"
condition:
$tw_secret
}

rule Twitter_Client_ID {
meta:
description = "Twitter client ID"
strings:
$tw_client = "(?i)twitter(.{0,20})?['"][0-9a-z]{18,25}['"]"
condition:
$tw_client
}

rule Github_Key {
meta:
description = "Github key"
strings:
$github = "(?i)github(.{0,20})?(?-i)['"][0-9a-zA-Z]{35,40}['"]"
condition:
$github
}

rule Heroku_API_key {
meta:
description = "Matches Heroku API key in contents"
strings:
$secret = /(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/
condition:
$secret
}

rule LinkedIn_Client_ID {
meta:
description = "Matches LinkedIn Client ID in contents"
strings:
$client_id = /(?i)linkedin(.{0,20})?(?-i)['"][0-9a-z]{12}['"]/
condition:
$client_id
}

rule LinkedIn_Secret_Key {
meta:
description = "Matches LinkedIn Secret Key in contents"
strings:
$secret = /(?i)linkedin(.{0,20})?['"][0-9a-z]{16}['"]/
condition:
$secret
}

rule Jetbrains_WebServers_credentials {
meta:
description = "Matches webserver credentials in Jetbrains IDEs WebServers.xml file path"
strings:
$path = /.?idea[\/]WebServers.xml$/
condition:
$path
}


rule VSCode_SFTP_Details_and_Credentials {
meta:
description = "Matches VSCode sftp.json file containing SFTP/SSH server details and credentials"
author = "ChatGPT"
strings:
$path = /.?vscode[\/]sftp.json$/
condition:
$path
}

rule Ruby_Rails_secrets_yml {
meta:
description = "Matches Ruby on Rails secrets.yml file containing passwords"
author = "ChatGPT"
strings:
$path = /web[\/]ruby[\/]secrets.yml/
condition:
$path
}

rule Docker_Registry_Auth_File {
meta:
description = "Matches Docker registry authentication file"
author = "ChatGPT"
strings:
$path = /.?docker[\/]config.json$/
condition:
$path
}

rule Rails_Master_Key {
meta:
description = "Matches Rails master key used for decrypting credentials.yml.enc for Rails 5.2+"
author = "ChatGPT"
strings:
$path = /ruby[\/]config[\/]master.key$/
condition:
$path
}

rule Firefox_Saved_Passwords {
meta:
description = "Matches Firefox saved password collection file"
author = "ChatGPT"
strings:
$path = /.?mozilla[\/]firefox[\/]logins.json$/
condition:
$path
}

rule Bitcoin_Core_Wallet {
meta:
description = "Matches Bitcoin Core wallet file"
author = "ChatGPT"
strings:
$file = "wallet.dat"
condition:
$file
}

rule Bitcoin_Core_Onion_Service_Private_Key {
meta:
description = "Matches private key file for Bitcoin Core onion service"
author = "ChatGPT"
strings:
$file = "onion_v3_private_key"
condition:
$file
}

rule Bitcoin_Core_Config {
meta:
description = "Matches Bitcoin Core config file"
author = "ChatGPT"
strings:
$file = "bitcoin.conf"
condition:
$file
}












