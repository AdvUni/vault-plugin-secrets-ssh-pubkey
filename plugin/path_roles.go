// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type role struct {
	RoleName              string
	UserName              string
	KeyOptionSpecs        string         `mapstructure:"key_option_specs" json:"key_option_specs"`
	AllowedUserKeyLengths map[string]int `mapstructure:"allowed_user_key_lengths" json:"allowed_user_key_lengths"`
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.listRoles,
		},

		HelpSynopsis:    pathRoleSyn,
		HelpDescription: pathRoleDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
				[Required] Name of the role being created. This is part of the request URL.`,
			},
			"username": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
				[Required] Name of the user at the host machine which is managed by this role.
				`,
			},
			"key_option_specs": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
				[Optional] Comma separated option specifications which will be prefixed to RSA key in
				authorized_keys file. Options should be valid and comply with authorized_keys
				file format and should not contain spaces.
				`,
			},
			//			"ttl": &framework.FieldSchema{
			//				Type: framework.TypeDurationSecond,
			//				Description: `
			//				[Not applicable for Dynamic type] [Not applicable for OTP type] [Optional for CA type]
			//				The lease duration if no specific lease duration is
			//				requested. The lease duration controls the expiration
			//				of certificates issued by this backend. Defaults to
			//				the value of max_ttl.`,
			//				DisplayAttrs: &framework.DisplayAttributes{
			//					Name: "TTL",
			//				},
			//			},
			//			"max_ttl": &framework.FieldSchema{
			//				Type: framework.TypeDurationSecond,
			//				Description: `
			//				[Not applicable for Dynamic type] [Not applicable for OTP type] [Optional for CA type]
			//				The maximum allowed lease duration
			//				`,
			//				DisplayAttrs: &framework.DisplayAttributes{
			//					Name: "Max TTL",
			//				},
			//			},
			"allowed_user_key_lengths": &framework.FieldSchema{
				Type: framework.TypeMap,
				Description: `
				[Optional] If set, allows the enforcement of key types and minimum
				key sizes to be signed.
                `,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.readRole,
			logical.UpdateOperation: b.writeRole,
			logical.DeleteOperation: b.deleteRole,
		},
		HelpSynopsis:    pathRoleSyn,
		HelpDescription: pathRoleDesc,
	}
}

func (b *backend) writeRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	r := role{}

	if roleName, ok := data.GetOk("role"); ok {
		r.RoleName = roleName.(string)
	} else {
		return logical.ErrorResponse("role attribute is required"), nil
	}
	if username, ok := data.GetOk("username"); ok {
		r.UserName = username.(string)
	} else {
		return logical.ErrorResponse("username attribute is required"), nil
	}
	if keyOptionSpecs, ok := data.GetOk("key_option_specs"); ok {
		r.KeyOptionSpecs = keyOptionSpecs.(string)
	}
	if allowedUserKeyLengths, ok := data.GetOk("allowed_user_key_lengths"); ok {
		var err error
		r.AllowedUserKeyLengths, err = convertMapToIntValue(allowedUserKeyLengths.(map[string]interface{}))
		if err != nil {
			return logical.ErrorResponse("malformed allowed_user_key_lengths parameter"), nil
		}
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("roles/%s", r.RoleName), r)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var roleName string
	if n, ok := data.GetOk("role"); ok {
		roleName = n.(string)
	} else {
		return logical.ErrorResponse("role attribute is required"), nil
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"role":                     role.RoleName,
			"username":                 role.UserName,
			"key_options_spec":         role.KeyOptionSpecs,
			"allowed_user_key_lengths": role.AllowedUserKeyLengths,
		},
	}
	return resp, nil
}

func (b *backend) deleteRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := ""
	if n, ok := data.GetOk("role"); ok {
		roleName = n.(string)
	} else {
		return logical.ErrorResponse("role attribute is required"), nil
	}

	if err := req.Storage.Delete(ctx, "roles/"+roleName); err != nil {
		return nil, err
	}

	return nil, nil
}

func getRole(ctx context.Context, s logical.Storage, roleName string) (*role, error) {
	entry, err := s.Get(ctx, "roles/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var r role
	if err := entry.DecodeJSON(&r); err != nil {
		return nil, err
	}

	return &r, nil
}

func (b *backend) listRoles(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

const pathRoleSyn = `
Manage the 'roles' that can be created with this backend.
`

const pathRoleDesc = `
This path is for managing the roles of the Secret Engine. Within the ssh-pubkey
plugin, a role is an association to a specific user at the target machine,
whereas the target machine itself is defined at endpoint 'config'.

A role is needed for using endpoint 'creds'.
`
