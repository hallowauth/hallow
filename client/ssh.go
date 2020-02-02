package client

import (
	"crypto"
	"io/ioutil"
	"os"
	"os/user"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"
)

func SSHCLI(signer crypto.Signer, sshCert ssh.PublicKey, server string) ([]string, error) {
	privKeyBytes, err := sshkeys.Marshal(signer, &sshkeys.MarshalOptions{
		Format: sshkeys.FormatOpenSSHv1,
	})
	if err != nil {
		return nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)

	tmpdir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpdir+"/id", privKeyBytes, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpdir+"/id-cert", certBytes, 0600)
	if err != nil {
		return nil, err
	}

	return []string{"ssh", "-i", tmpdir + "/id", server}, nil
}

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
