//This Source Code Form is subject to the terms of the Mozilla Public
//License, v. 2.0. If a copy of the MPL was not distributed with this
//file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	view      logical.Storage
	salt      *salt.Salt
	saltMutex sync.RWMutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.view = conf.StorageView
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/*",
			},
		},

		Paths: []*framework.Path{
			pathConfig(&b),
			pathRoles(&b),
			pathListRoles(&b),
			pathCreds(&b),
		},

		Secrets: []*framework.Secret{
			secretSSHPubkey(&b),
		},

		Invalidate:  b.invalidate,
		BackendType: logical.TypeLogical, // Type for Secret Engines
	}
	return &b
}

func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return salt, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	switch key {
	case salt.DefaultLocation:
		b.saltMutex.Lock()
		defer b.saltMutex.Unlock()
		b.salt = nil
	}
}

// TODO: improve help
const backendHelp = `
The ssh-pubkey Secrets Engine grants access to remote hosts with normal
ssh public key authentication.

This is a variantion of vault's builtin ssh secrets engine.
`
