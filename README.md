# Vault Plugin: SSH-Pubkey Secrets Engine

This is a secrets backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This secrets engine is for granting access to SSH machines.

It is a variation to Vaults [builtin SSH Secrets Engine](https://www.vaultproject.io/docs/secrets/ssh/index.html), providing something like fourth mode.

## Why another SSH Secrets Engine?
Vaults [builtin SSH Secrets Engine](https://www.vaultproject.io/docs/secrets/ssh/index.html) already provides three different modes for accessing SSH machines:
* [Signed SSH Certificates](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html)
* [One-time SSH Passwords](https://www.vaultproject.io/docs/secrets/ssh/one-time-ssh-passwords.html)
* [Dynamic SSH Keys](https://www.vaultproject.io/docs/secrets/ssh/dynamic-ssh-keys.html)

But they all have their drawbacks.

Although One-time Passwords are an elegant authentication mechanism, they just don't fit every use case.

The Dynamic Key mode is useful, but its handling of SSH keys is a bit weird. It generates key pairs and uploads the private key to the target machine's `authorized_keys` file while returning the private key to the user. Afterwards, the user can log into the target machine using the private key. This behavior kind of bypasses the advantages of public key authentication. Actually, the private key should always be generated by the user itself. Otherwise, SSH keys are nothing else than very unhandy passwords. The Dynamic Key mode was deprecated by HashiCorp anyway.

The alternative is the Signed certificates mode. It is identified by Vault as the "simplest and most powerful" mode. Here, a user provides its own public key to Vault. The Secrets Engine signs it with its own private key and returns the signature in form of a certificate to the user. The user now can use its own private key together with the certificate and log into every SSH machine, where the Secrets Engine's public key is registered as CA. This is an elegant solution since no private keys have to be transmitted during the signing process and each user can use its personal key pair for as many signing requests as he wishes. 

But so the user needs to provide two files for authentication, both the certificate and the private key. Further, the certificate changes for each signing request, so it must be downloaded from the Secrets Engine each time. Another flaw is, that Vault has no possibility to revoke certificates, ones they are created. Hence the Signed Certificate mode does not create [Leases](https://www.vaultproject.io/docs/concepts/lease.html) providing the advantages of [Dynamic Secrets](https://www.hashicorp.com/blog/why-we-need-dynamic-secrets), as advertised by HashiCorp.

So why there is not another mode, which combines the dynamic keys and the signed certificates? This is what the SSH-Pubkey plugin tries to accomplish. It uploads SSH public keys to the `authorized_keys` file of a target machine allowing the owner of the private key to log in, but it requests the public key from the user instead of generating it itself. Further, the Secrets Engine returns a lease with the possibility to renew or revoke the access immediately. As long as the lease is valid, users can do real public key authentication towards the target machine only using their personal key pair without copying, downloading or forwarding any information from Vault at all. They can even use the same keys over different leases.

## Code and functionality
This Plugin was written by copying and modifying the [Code from the builtin SSH Secrets Engine](https://github.com/hashicorp/vault/tree/master/builtin/logical/ssh). Since the plugin does not include several modes at once, it is much simpler than the original Secrets Engine.

## Usage
You can find the API reference under [doc/api_reference.md](doc/api_reference.md)