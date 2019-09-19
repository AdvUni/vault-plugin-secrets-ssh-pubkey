// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/helper/parseutil"

	log "github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/ssh"
)

const (
	invalidTimestringMsg = "invalid timestring for %s. Must have a format like '30s or '1h20m'. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h"
)

// Public key and the script to install the key are uploaded to remote machine.
// Public key is either added or removed from authorized_keys file using the
// script. Default script is for a Linux machine and hence the path of the
// authorized_keys file is hard coded to resemble Linux.
//
// The last param 'install' if false, uninstalls the key.
func (b *backend) installPublicKeyInTarget(ctx context.Context, adminUser, username, ip string, port int, hostkey, dynamicPublicKey, installScript string, install bool) error {
	// Transfer the newly generated public key to remote host under a random
	// file name. This is to avoid name collisions from other requests.
	_, publicKeyFileName, err := b.GenerateSaltedOTP(ctx)
	if err != nil {
		return err
	}

	comm, err := createSSHComm(b.Logger(), adminUser, ip, port, hostkey)
	if err != nil {
		return err
	}
	defer comm.Close()

	err = comm.Upload(publicKeyFileName, bytes.NewBufferString(dynamicPublicKey), nil)
	if err != nil {
		return errwrap.Wrapf("error uploading public key: {{err}}", err)
	}

	// Transfer the script required to install or uninstall the key to the remote
	// host under a random file name as well. This is to avoid name collisions
	// from other requests.
	scriptFileName := fmt.Sprintf("%s.sh", publicKeyFileName)
	err = comm.Upload(scriptFileName, bytes.NewBufferString(installScript), nil)
	if err != nil {
		return errwrap.Wrapf("error uploading install script: {{err}}", err)
	}

	// Create a session to run remote command that triggers the script to install
	// or uninstall the key.
	session, err := comm.NewSession()
	if err != nil {
		return errwrap.Wrapf("unable to create SSH Session using public keys: {{err}}", err)
	}
	if session == nil {
		return fmt.Errorf("invalid session object")
	}
	defer session.Close()

	authKeysFileName := fmt.Sprintf("/home/%s/.ssh/authorized_keys", username)

	var installOption string
	if install {
		installOption = "install"
	} else {
		installOption = "uninstall"
	}

	// Give execute permissions to install script, run and delete it.
	chmodCmd := fmt.Sprintf("chmod +x %s", scriptFileName)
	scriptCmd := fmt.Sprintf("./%s %s %s %s", scriptFileName, installOption, publicKeyFileName, authKeysFileName)
	rmCmd := fmt.Sprintf("rm -f %s", scriptFileName)
	targetCmd := fmt.Sprintf("%s;%s;%s", chmodCmd, scriptCmd, rmCmd)

	session.Run(targetCmd)
	return nil
}

func createSSHComm(logger log.Logger, username, ip string, port int, hostkey string) (*comm, error) {
	signer, err := ssh.ParsePrivateKey([]byte(hostkey))
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	connfunc := func() (net.Conn, error) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 15*time.Second)
		if err != nil {
			return nil, err
		}

		if tcpConn, ok := c.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(5 * time.Second)
		}

		return c, nil
	}
	config := &SSHCommConfig{
		SSHConfig:    clientConfig,
		Connection:   connfunc,
		Pty:          false,
		DisableAgent: true,
		Logger:       logger,
	}

	return SSHCommNew(fmt.Sprintf("%s:%d", ip, port), config)
}

func parsePublicSSHKey(key string) (ssh.PublicKey, error) {
	keyParts := strings.Split(key, " ")
	if len(keyParts) > 1 {
		// Someone has sent the 'full' public key rather than just the base64 encoded part that the ssh library wants
		key = keyParts[1]
	}

	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey([]byte(decodedKey))
}

func convertMapToStringValue(initial map[string]interface{}) map[string]string {
	result := map[string]string{}
	for key, value := range initial {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func convertMapToIntValue(initial map[string]interface{}) (map[string]int, error) {
	result := map[string]int{}
	for key, value := range initial {
		v, err := parseutil.ParseInt(value)
		if err != nil {
			return nil, err
		}
		result[key] = int(v)
	}
	return result, nil
}

// Serve a template processor for custom format inputs
func substQuery(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.Replace(tpl, fmt.Sprintf("{{%s}}", k), v, -1)
	}

	return tpl
}
