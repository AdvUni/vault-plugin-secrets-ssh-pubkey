// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const secretSSHPubkeyType = "secret_ssh_pubkey_type"

func secretSSHPubkey(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretSSHPubkeyType,
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username in host",
			},
			"publicKey": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ssh public key in authorized_key file",
			},
		},

		Renew:  b.secretSSHPubkeyRenew,
		Revoke: b.secretSSHPubkeyRevoke,
	}
}

func (b *backend) secretSSHPubkeyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{Secret: req.Secret}, nil
}

func (b *backend) secretSSHPubkeyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	type sec struct {
		Username  string `mapstructure:"username"`
		PublicKey string `mapstructure:"public_key"`
	}

	intSec := &sec{}
	err := mapstructure.Decode(req.Secret.InternalData, intSec)
	if err != nil {
		return nil, fmt.Errorf("secret internal data could not be decoded: %s", err)
	}

	config, err := getConfigParams(ctx, req.Storage)
	if err != nil || config == nil {
		return nil, fmt.Errorf("did not find config during revokation of ssh public key: %v", err)
	}

	// Remove the public key from authorized_keys file in target machine
	// The last param 'false' indicates that the key should be uninstalled.
	err = b.installPublicKeyInTarget(ctx, config.SSHuser, intSec.Username, config.URL, config.Port, config.PrivateKey, intSec.PublicKey, config.InstallScript, false)
	if err != nil {
		return nil, fmt.Errorf("error removing public key from authorized_keys file in target")
	}
	return nil, nil
}
