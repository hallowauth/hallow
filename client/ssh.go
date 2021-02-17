package client

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
)

// SSHCLI will write out key material to a tempfile and return a command to be
// exec'd.
func SSHCLI(signer crypto.Signer, sshCert ssh.PublicKey, sshArgs ...string) ([]string, error) {
	keyFormat := sshkeys.FormatClassicPEM
	if _, ok := signer.(ed25519.PrivateKey); ok {
		keyFormat = sshkeys.FormatOpenSSHv1
	}

	privKeyBytes, err := sshkeys.Marshal(signer, &sshkeys.MarshalOptions{
		Format: keyFormat,
	})
	if err != nil {
		return nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshCert.(*ssh.Certificate).Key)

	tmpdir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpdir+"/id", privKeyBytes, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpdir+"/id.pub", pubKeyBytes, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpdir+"/id-cert.pub", certBytes, 0600)
	if err != nil {
		return nil, err
	}

	return append([]string{"ssh", "-o", fmt.Sprintf("IdentityFile %s/id", tmpdir)}, sshArgs...), nil
}

// DefaultComment will create the default ssh key comment given the local
// envrionment. The default option will be to construct username@hostname.
//
// If the username can not be determined, it will default to 'hallow'.
// If the hostname can not be determined, it will default to the username.
func DefaultComment() string {
	u, err := user.Current()
	if err != nil {
		return "hallow"
	}

	hostname, err := os.Hostname()
	if err != nil {
		return u.Username
	}
	return u.Username + "@" + hostname
}
