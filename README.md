# Vault Plugin: SSH-Pubkey Secrets Engine

This is a secrets backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This Secrets Engine is for granting access to SSH machines.

It is a variation of Vaults [builtin SSH Secrets Engine](https://www.vaultproject.io/docs/secrets/ssh/index.html), providing something like a fourth mode. It offers SSH access through normal public key authentication.

All functions of the Secrets Engine are fully documented in the [API reference](doc/api_reference.md).

## Why another SSH Secrets Engine?
Vaults [builtin SSH Secrets Engine](https://www.vaultproject.io/docs/secrets/ssh/index.html) already provides three different modes for accessing SSH machines:
* [Signed SSH Certificates](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html)
* [One-time SSH Passwords](https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html)
* [Dynamic SSH Keys](https://www.vaultproject.io/docs/secrets/ssh/dynamic-ssh-keys.html)

But they all have their drawbacks.

Although One-time Passwords are an elegant authentication mechanism, they just don't fit every use case.

The Dynamic Key mode is useful, but its handling of SSH keys is a bit weird. It generates key pairs and uploads the private key to the target machine's `authorized_keys` file while returning the private key to the user. Afterwards, the user can log into the target machine using the private key. This behavior kind of bypasses the advantages of public key authentication. Actually, the private key should always be generated by the user himself. Otherwise, SSH keys not differ much from very unhandy passwords. The Dynamic Key mode was deprecated by HashiCorp anyway.

The alternative is the Signed certificates mode. It is identified by Vault as the "simplest and most powerful" mode. Here, a user provides his own public key to Vault. The Secrets Engine has a key pair itself and uses it to sign the user's key. Then it returns the signature in form of a certificate to the user. The user now can use its own private key together with the certificate and log into every SSH machine, where the Secrets Engine's public key is registered as CA. This is an elegant solution since no private keys have to be transmitted during the signing process and each user can use its personal key pair for as many signing requests as he wishes. 

But so the user needs to provide two files for authentication, both the certificate and the private key. Further, the certificate changes for each signing request, so it must be downloaded from the Secrets Engine each time. Another flaw is, that Vault has no possibility to revoke certificates once they are created. Hence the Signed Certificate mode does not create [Leases](https://www.vaultproject.io/docs/concepts/lease.html) providing the advantages of [Dynamic Secrets](https://www.hashicorp.com/blog/why-we-need-dynamic-secrets), as advertised by HashiCorp.

So why there is not another mode, which combines the modes dynamic keys and signed certificates? This is what the SSH-Pubkey plugin tries to accomplish. It uploads SSH public keys to the `authorized_keys` file of a target machine allowing the owner of the private key to log in, but it requests the public key from the user instead of generating it itself. Further, the Secrets Engine returns a lease with the possibility to renew or revoke the access immediately. As long as the lease is valid, users can do real public key authentication towards the target machine only using their personal key pair without copying, downloading or forwarding any information from Vault at all. The same keys can be used over different leases.

## Usage
Download the code with
```sh
go get -u github.com/AdvUni/vault-plugin-secrets-ssh-pubkey
```
Move into `~/github.com/AdvUni/vault-plugin-secrets-ssh-pubkey` and compile the plugin with
```sh
go build -o ssh-pubkey-plugin
```

Next, the plugin needs to be [registered](https://www.vaultproject.io/docs/internals/plugins.html#plugin-registration) in vault. Note that you therefore need to specify a [plugin directory](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory) and the [api-address parameter](https://www.vaultproject.io/docs/configuration/index.html#api_addr) in your vault configuration first. 

Enable the plugin, configure it and define a role. Then, the `creds` endpoint can be used to grant an ssh key access to the target machine:
```sh
vault write ssh-pubkey/creds/my_role public_key="ssh-rsa AAAAB3NzaC1yc2EAA..."
```
Afterwards, the corresponding private key can be used for logging into the target machine via normal public key authentication:
```sh
ssh -i id_rsa user@example-url
```
if the ssh key pair lays in the `.ssh` folder in your home directory, you can even omit to specify it with the `-i` parameter.

For full reference see the API documentation under [doc/api_reference.md](doc/api_reference.md)

## Code and functionality
This Plugin was written by copying and modifying the [Code from the builtin SSH Secrets Engine](https://github.com/hashicorp/vault/tree/master/builtin/logical/ssh). The SSH-Pubkey plugin not includes the functionality of several modes at once and is therefore much simpler than the original Secrets Engine.

In particular, the tasks of the different request endpoints 'config', 'role' and 'creds' are determined a bit more clearly. Each instance of the SSH-Pubkey Secrets Engine addresses one specific target machine. This target machine is determined by URL or IP address at the endpoint `creds`. A role in contrast is for addressing one specific OS user at the target machine. This user's `authorized_keys` file gets changed when calling endpoint `creds` for the role. You always need a role for calling the `creds` endpoint.

With this concepts, there is no possibility for users to ask for custom IPs when requesting `creds` as in the builtin SSH Secrets Engine. Neither is there any need for specifying parameters like allowed CIDR blocks or Zero-Addresses.