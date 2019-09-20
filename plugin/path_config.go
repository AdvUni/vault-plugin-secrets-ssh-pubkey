// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type config struct {
	URL           string
	Port          int
	SSHuser       string
	PrivateKey    string
	PublicKey     string
	InstallScript string
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Required] URL or IP address of target machine.",
			},
			"port": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "[Optional] Port number which is used by Secrets Engine to communicate with target machine. Default is 22.",
			},
			"ssh_user": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Optional] Privileged user who has access to authorized_key files. Default is 'root'.",
			},
			"private_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Required] SSH private key which has permissions to log into 'ssh_user'.",
			},
			"public_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Required] SSH public key belonging to the private key. It is only for reference purposes. When making a GET request on the config, it shows up instead of the private key",
			},
			"install_script": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "[Optional] Script used to install and uninstall public keys in the target machine. The inbuilt default install script will be for Linux hosts. It can be found within the plugin code inside the file plugin/linux_install_script.go.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeConfig,
			logical.DeleteOperation: b.deleteConfig,
			logical.ReadOperation:   b.readConfig,
		},
		HelpSynopsis:    pathConfigSyn,
		HelpDescription: pathConfigDesc,
	}
}

func pathConfigInstallScript(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/install_script",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.readInstallScript,
		},
		HelpSynopsis:    "Look up the configured install_script.",
		HelpDescription: "As the install script is quite long, it is not included in the response to a read request on path config. Instead, the script can be reviewed using this endpoint. It is only for reading purposes and does not support write requests. To set the script, use endpoint config.",
	}
}

func (b *backend) readConfig(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfigParams(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"url":        config.URL,
			"port":       config.Port,
			"ssh_user":   config.SSHuser,
			"public_key": config.PublicKey,
		},
	}
	return resp, nil
}

func (b *backend) readInstallScript(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfigParams(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"install_script": config.InstallScript,
		},
	}
	return resp, nil
}

func (b *backend) deleteConfig(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) writeConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c := config{}

	// unpack config parameters from request
	if url, ok := data.GetOk("url"); ok {
		c.URL = url.(string)
	} else {
		return logical.ErrorResponse("url parameter is required"), nil
	}
	if port, ok := data.GetOk("port"); ok {
		c.Port = port.(int)
	} else {
		c.Port = 22
	}
	if sshUser, ok := data.GetOk("ssh_user"); ok {
		c.SSHuser = sshUser.(string)
	} else {
		c.SSHuser = "root"
	}
	if privateKey, ok := data.GetOk("private_key"); ok {
		c.PrivateKey = privateKey.(string)
	} else {
		return logical.ErrorResponse("private key parameter is required"), nil
	}
	if publicKey, ok := data.GetOk("public_key"); ok {
		c.PublicKey = publicKey.(string)
	} else {
		return logical.ErrorResponse("public key parameter is required"), nil
	}
	if installScript, ok := data.GetOk("install_script"); ok {
		c.InstallScript = installScript.(string)
	} else {
		// Setting the default script here. The script will install the
		// generated public key in the authorized_keys file of linux host.
		c.InstallScript = DefaultPublicKeyInstallScript
	}

	// validate keys
	pr, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
	if err != nil || pr == nil {
		return logical.ErrorResponse("invalid private key"), nil
	}
	pu, err := parsePublicSSHKey(c.PublicKey)
	if err != nil || pu == nil {
		return logical.ErrorResponse("invalid public key"), nil
	}

	// store config
	entry, err := logical.StorageEntryJSON("config", &c)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func getConfigParams(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var c config
	if err := entry.DecodeJSON(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

const pathConfigSyn = `
Configure the host machine with which this Secrets Engine communicates. 
`

const pathConfigDesc = `
Each ssh-pubkey Secrets Engine instance is meant to communicate with one target
maschine. The 'config' endpoint is for storing the connection parameters. Those
are the maschine's URL/IP and the ssh key pair of a privileged user on the
target maschine, which can be used to access the maschine's authorized_keys
files.
`
