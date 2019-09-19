// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Required] Name of the role",
			},
			"public_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Required] The ssh public key to register within the target machine",
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
				[Optional] The lease duration if no specific lease duration is
				requested. The lease duration controls the expiration
				of certificates issued by this backend. Defaults to
				the value of max_ttl.`,
			},
			"max_ttl": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
				[Optional] The maximum allowed lease duration
				`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.registerKeyInTargetMachine,
		},
		HelpSynopsis:    pathCredsSyn,
		HelpDescription: pathCredsDesc,
	}
}

func (b *backend) registerKeyInTargetMachine(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// fetch role
	roleName, ok := data.GetOk("role")
	if !ok || roleName == "" {
		return logical.ErrorResponse("role parameter is required"), nil
	}
	role, err := getRole(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	// fetch secrets engine config
	config, err := getConfigParams(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("secrets engine hasn't been configured yet"), nil
	}

	// get key from arguments and validate
	var pubKeyString string
	if pubkey, ok := data.GetOk("public_key"); ok {
		pubKeyString = pubkey.(string)
	} else {
		return logical.ErrorResponse("public_key parameter is required"), nil
	}
	publicKey, err := parsePublicSSHKey(pubKeyString)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to parse public_key as SSH key: %s", err)), nil
	}

	// get ttl and max_ttl from arguments and validate
	var ttl, ttlMax time.Duration
	if ttlString, ok := data.GetOk("ttl"); ok {
		ttl, err = time.ParseDuration(ttlString.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(invalidTimestringMsg, "ttl")), nil
		}
		if role.TTL != 0 && ttl > role.TTL {
			return logical.ErrorResponse("ttl is to big. The role config only allows a ttl up to %s", role.TTL.String()), nil
		}
	} else {
		ttl = role.TTL
	}
	if ttlMaxString, ok := data.GetOk("max_ttl"); ok {
		ttlMax, err = time.ParseDuration(ttlMaxString.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(invalidTimestringMsg, "max_ttl")), nil
		}
		if role.MaxTTL != 0 && ttlMax > role.MaxTTL {
			return logical.ErrorResponse("max_ttl is to big. The role config only allows a max_ttl up to %s", role.MaxTTL.String()), nil
		}
	} else {
		ttlMax = role.MaxTTL
	}

	// apply the role's AllowUserKeyLength
	err = b.validateSignedKeyRequirements(publicKey, role)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("public_key failed to meet the key requirements: %s", err)), nil
	}

	// add KeyOptionSpecs to the key string before copying on target machine
	if role.KeyOptionSpecs != "" {
		pubKeyString = fmt.Sprintf("%s %s", role.KeyOptionSpecs, pubKeyString)
	}

	// add the public key to authorized_keys file in target machine
	err = b.installPublicKeyInTarget(ctx, config.SSHuser, role.UserName, config.URL, config.Port, config.PrivateKey, pubKeyString, config.InstallScript, true)
	if err != nil {
		return nil, fmt.Errorf("failed to add public key to authorized_keys file in target: %v", err)
	}

	responseData := map[string]interface{}{
		"username":   role.UserName,
		"public_key": pubKeyString,
	}

	resp := b.Secret(secretSSHPubkeyType).Response(responseData, responseData)

	// set lease duration and max duration if given
	if ttl != 0 {
		resp.Secret.TTL = ttl
	}
	if ttlMax != 0 {
		resp.Secret.MaxTTL = ttlMax
	}

	return resp, nil
}

// Generates a UUID OTP and its salted value based on the salt of the backend.
func (b *backend) GenerateSaltedOTP(ctx context.Context) (string, string, error) {
	str, err := uuid.GenerateUUID()
	if err != nil {
		return "", "", err
	}
	salt, err := b.Salt(ctx)
	if err != nil {
		return "", "", err
	}

	return str, salt.SaltID(str), nil
}

func (b *backend) validateSignedKeyRequirements(publickey ssh.PublicKey, role *role) error {
	if len(role.AllowedUserKeyLengths) != 0 {
		var kstr string
		var kbits int

		switch k := publickey.(type) {
		case ssh.CryptoPublicKey:
			ff := k.CryptoPublicKey()
			switch k := ff.(type) {
			case *rsa.PublicKey:
				kstr = "rsa"
				kbits = k.N.BitLen()
			case *dsa.PublicKey:
				kstr = "dsa"
				kbits = k.Parameters.P.BitLen()
			case *ecdsa.PublicKey:
				kstr = "ecdsa"
				kbits = k.Curve.Params().BitSize
			case ed25519.PublicKey:
				kstr = "ed25519"
			default:
				return fmt.Errorf("public key type of %s is not allowed", kstr)
			}
		default:
			return fmt.Errorf("pubkey not suitable for crypto (expected ssh.CryptoPublicKey but found %T)", k)
		}

		if value, ok := role.AllowedUserKeyLengths[kstr]; ok {
			var pass bool
			switch kstr {
			case "rsa":
				if kbits == value {
					pass = true
				}
			case "dsa":
				if kbits == value {
					pass = true
				}
			case "ecdsa":
				if kbits == value {
					pass = true
				}
			case "ed25519":
				// ed25519 public keys are always 256 bits in length,
				// so there is no need to inspect their value
				pass = true
			}

			if !pass {
				return fmt.Errorf("key is of an invalid size: %v", kbits)
			}

		} else {
			return fmt.Errorf("key type of %s is not allowed", kstr)
		}
	}
	return nil
}

const pathCredsSyn = `
Grants access to an ssh public key at target machine.
`

const pathCredsDesc = `
The 'creds' endpoint takes a role name and an ssh public key. The Secrets
Engine writes the key into the authorized_keys file for the user
defined by the role. So, the owner of the associated private key can log
into the target machine afterwards.
`

//Keys will have a lease associated with them. The access keys can be
//revoked by using the lease ID.
//`
