# SSH-pubkey Secrets Engine API Reference
This is the API documentation for the SSH-pubkey Secrets Engine. This Secrets Engine is a variation of the builtin SSH Secrets Engine. As it is not a native Vault Plugin you have to [register](https://www.vaultproject.io/docs/internals/plugins.html#plugin-registration) it before you can enable it. Also make sure to include the parameter [`api_addr`](https://www.vaultproject.io/docs/configuration/#api_addr) in your vault config; otherwise the plugin communication does not function.

The ssh-pubkey Secrets Engine provides access to an SSH machine through registering SSH public keys at the machine's authorized_keys file. But in contrast to the builtin [SSH Secrets Engine in dynamic key mode](https://www.vaultproject.io/docs/secrets/ssh/dynamic-ssh-keys.html), it does not generate this key itself, but takes it from the user during a `creds` request, similar to the builtin [SSH Secrets Engine in signed certificates mode](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html). This mode again only signs the provided key instead of uploading it. Hence, the advantage of the ssh-pubkey plugin is that users don't need to use certificates or any information from the Secrets Engine at all. After performing a `creds` request, they can log in immediately with their own public key. They don't even need to change the keys over different leases.

This documentation assumes that you registerd the Secrets Engine with the name 'ssh-pubkey' and that is enabled at the `/ssh-pubkey` path in Vault. Since it is possible to enable secrets engines at any location, please update your API calls accordingly.

## Upload Configuration
Within the logic of this plugin, each instance of the Secrets Engine is associated with exactly one SSH target machine. The `config` endpoint specifies the connection parameters to this machine. 

Method | Path 
-------|-------------
POST   | ssh-pubkey/config
GET    | ssh-pubkey/config
DELETE | ssh-pubkey/config

### Parameters
* `url` (string, required) – URL or IP address of SSH target machine.
* `port` (integer, optional) – Port number which is used by Secrets Engine to communicate with target machine. Default is 22.
* `ssh_user` (string, optional) – Privileged user who has access to authorized_key files. Default is 'root'.
* `private_key` (string, required) – SSH private key which has permissions to log into 'ssh_user'. Note, that private keys usually contain line breaks which are not allowed in json strings. So, you first must encode them with `\n`.
* `public_key` (string, required) – SSH public key belonging to the private key. It is only for reference purposes. When making a GET request on the config, it shows up instead of the private key.
* `install_script` (string, optional) – Script used to install and uninstall public keys in the target machine.	The inbuilt default install script will be for Linux hosts. It can be found within the plugin code inside the file [plugin/linux_install_script.go](../plugin/linux_install_script.go). (Or see example response of endpoint [config/install_script](./api_reference.md#read-install-script))

### Sample POST Payload
```json
{
    "url":"127.0.0.1",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n ...",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAA..."
}
```

### Sample POST Request
```sh
curl \
    --header 'X-Vault-Token: '"$VAULT_TOKEN"'' \
    --request POST \
    --data @sshpubkey_config.json \
    http://127.0.0.1:8200/v1/ssh-pubkey/config
```

### Sample GET Response Data
```json
{
    "port":22,
    "public_key":"ssh-rsa AAAAB3NzaC1yc2EAA...",
    "ssh_user":"root",
    "url":"127.0.0.1"
}
```
As the `install_script` is quite long, it is not included in the output. To review the `install_script`, use endpoint `config/install_script` instead.

### Read install script

Method | Path 
-------|-------------
GET    | ssh-pubkey/config/install_script

As the `install_script` is quite long, it is not included in the response to a GET request at endpoint `config`. To have a possibility to review the script anyway, there is this extra endpoint. It is only for reading the script. As the script is part of the Secrets Engine's configuration, it is set at path `config`.

### Sample GET Request
```sh
curl \
    --header 'X-Vault-Token: '"$VAULT_TOKEN"'' \
    http://127.0.0.1:8200/v1/ssh-pubkey/config/install_script
```

### Sample GET Response Data
```json
{
    "install_script":"\n
    #!/bin/bash\n
    #\n
    # This is a default script which installs or uninstalls an RSA public key to/from\n
    # authorized_keys file in a typical linux machine.\n
    #\n
    # If the platform differs or if the binaries used in this script are not available\n
    # in target machine, use the 'install_script' parameter with 'roles/' endpoint to\n
    # register a custom script (applicable for Dynamic type only).\n
    #\n
    # Vault server runs this script on the target machine with the following params:\n
    #\n
    # $1:INSTALL_OPTION: \"install\" or \"uninstall\"\n
    #\n
    # $2:PUBLIC_KEY_FILE: File name containing public key to be installed. Vault server\n
    # uses UUID as name to avoid collisions with public keys generated for other requests.\n
    #\n
    # $3:AUTH_KEYS_FILE: Absolute path of the authorized_keys file.\n
    # Currently, vault uses /home/\u003cusername\u003e/.ssh/authorized_keys as the path.\n
    #\n
    # [Note: This script will be run by Vault using the registered admin username.\n
    # Notice that some commands below are run as 'sudo'. For graceful execution of\n
    # this script there should not be any password prompts. So, disable password\n
    # prompt for the admin username registered with Vault.\n
    \n
    set -e\n
    \n
    # Storing arguments into variables, to increase readability of the script.\n
    INSTALL_OPTION=$1\nPUBLIC_KEY_FILE=$2\nAUTH_KEYS_FILE=$3\n
    \n
    # Delete the public key file and the temporary file\n
    function cleanup\n
    {\n\t
        rm -f \"$PUBLIC_KEY_FILE\" temp_$PUBLIC_KEY_FILE\n
    }\n
    \n
    # 'cleanup' will be called if the script ends or if any command fails.\n
    trap cleanup EXIT\n
    \n
    # Return if the option is anything other than 'install' or 'uninstall'.\n
    if [ \"$INSTALL_OPTION\" != \"install\" ] \u0026\u0026 [ \"$INSTALL_OPTION\" != \"uninstall\" ]; then\n\t
        exit 1\n
    fi\n
    \n
    # use locking to avoid parallel script execution\n
    (\n\t
        flock --timeout 10 200\n\t
        # Create the .ssh directory and authorized_keys file if it does not exist\n\t
        SSH_DIR=$(dirname $AUTH_KEYS_FILE)\n\t
        sudo mkdir -p \"$SSH_DIR\"\n\t
        sudo touch \"$AUTH_KEYS_FILE\"\n\t
        # Remove the key from authorized_keys file if it is already present.\n\t
        # This step is common for both install and uninstall.  Note that grep's\n\t
        # return code is ignored, thus if grep fails all keys will be removed\n\t
        # rather than none and it fails secure\n\t
        sudo grep -vFf \"$PUBLIC_KEY_FILE\" \"$AUTH_KEYS_FILE\" \u003e temp_$PUBLIC_KEY_FILE || true\n\t
        cat temp_$PUBLIC_KEY_FILE | sudo tee \"$AUTH_KEYS_FILE\"\n\t
        # Append the new public key to authorized_keys file\n\t
        if [ \"$INSTALL_OPTION\" == \"install\" ]; then\n\t\t
            cat \"$PUBLIC_KEY_FILE\" | sudo tee --append \"$AUTH_KEYS_FILE\"\n\t
        fi\n
    ) 200\u003e ${AUTH_KEYS_FILE}.lock\n"
}
```

## Manage Roles
Within the logic of this plugin, a role defines *for which* OS user this Secrets Engine provides access. So, one instance of this Secrets Engine can manage access to different users at the same machine through definement of several roles. The `roles` endpoint is to create, read, and delete roles. 

Method | Path 
-------|-------------
LIST   | ssh-pubkey/roles
POST   | ssh-pubkey/roles/:role_name
GET    | ssh-pubkey/roles/:role_name
DELETE | ssh-pubkey/roles/:role_name

### Parameters
* `role` (string, required) – Specifies the name of the role to create. This is part of the request URL.
* `username` (string, required)  –   Name of the target machine's OS user which is managed by this role.
* `ttl` (string, optional) – The role's default lease duration. It controls a public key's duration of access after a creds request. At request time, the ttl can be set individually, but not be greater than the role's default. The ttl overwrites the system/mount default. If max_ttl is given, ttl defaults to the value of max_ttl. The duration string must have a format like '30s or '1h20m'. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.
* `max_ttl` (string, optional) – The role's default maximum allowed lease duration. A lease can be renewed until this value gets reached. At request time, the max_ttl can be set individually, but not be greater than the role's default. The max_ttl overwrites the system/mount default. The duration string must have a format like '30s or '1h20m'. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.
* `key_option_specs` (string, optional) – Comma separated option specifications which will be prefixed to public RSA keys before uploading to authorized_keys file. Options should be valid and comply with authorized_keys file format and should not contain spaces.
* `allowed_user_key_lengths` (map`<string|int>`) – Specifies a map of ssh key types and their expected sizes which are allowed to be signed by the CA type.

### Sample POST Payload
```json
{
    "username": "example_user",
    "ttl": "1h30m",
    "max_ttl": "24h"
}
```

### Sample POST Request
```sh
curl \
    --header 'X-Vault-Token: '"$VAULT_TOKEN"'' \
    --request POST \
    --data @sshpubkey_role.json \
    http://127.0.0.1:8200/v1/ssh-pubkey/roles/my_role
```

### Sample GET Response Data
```json
{
    "allowed_user_key_lengths":null,
    "key_options_spec":"",
    "max_ttl":"24h",
    "role":"my_role",
    "ttl":"1h30m",
    "username":"example_user"
}
```

## Create Lease
The `creds` endpoint grants access to the target machine. As the Secrets Engine uploads the provided public key of the user to the machine's `authorized_keys` file, it does not generate credentials nor exactly provide them at all. Nevertheless this endpoint is called `creds` as the functionality is comparable with other Secrets Engines.

Method | Path 
-------|-------------
POST   | ssh-pubkey/creds/:role_name

### Parameters
* `role` (string, required) – Role name for which the public key should be uploaded. This is part of the request URL.
* `public_key` (string, required) – The ssh public key to register within the target machine.
* `ttl` (string, optional) – The lease duration. After its expiration, vault will remove the public key from the target machine automatically. Value can not be greater than the ttl in the role definition. Defaults to the role's ttl. The duration string must have a format like '30s or '1h20m'. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.
* `max_ttl` (string, optional) – The maximum allowed lease duration. This determines, how often the lease can be renewed. Value can not be greater than the max_ttl in the role definition. Defaults to the role's max_ttl. The duration string must have a format like '30s or '1h20m'. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.

### Sample POST Payload
```json
{
  "public_key": "ssh-rsa ..."
}
```

### Sample POST Request
```sh
curl \
    --header 'X-Vault-Token: '"$VAULT_TOKEN"'' \
    --request POST \
    --data @sshpubkey_creds.json \
    http://127.0.0.1:8200/v1/ssh-pubkey/creds/my_role
```
