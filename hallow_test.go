package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCreatePrincipalName(t *testing.T) {
	for _, c := range []struct {
		arn      string
		expected string
	}{
		{
			arn:      "arn:aws:sts::12345:assumed-role/my-role/comment",
			expected: "arn:aws:sts::12345:assumed-role/my-role",
		},
		{
			arn:      "arn:aws:iam::12345:user/john-doe",
			expected: "arn:aws:iam::12345:user/john-doe",
		},
	} {
		t.Run(c.arn, func(t *testing.T) {
			parsedArn, err := arn.Parse(c.arn)
			require.NoError(t, err)

			principal, err := createPrincipalName(parsedArn)
			require.NoError(t, err)
			require.Equal(t, principal, c.expected)
		})
	}
}

func TestValidatePublicKey(t *testing.T) {
	h := config{}

	for _, c := range []struct {
		pubKey      string
		expectedErr error
	}{
		// Valid keys.
		{
			pubKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
		},
		{
			pubKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKEKlDRLGPX1iKEGebvigYpkydGfuok6WQYROznG8XFyH1Se7/p1pXADdJtrnegU2Qn3jgmevHvDKD5VAIyGpB8=",
		},
		{
			pubKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCn9+7X+Uk8NSi7Dv6BRkKLVKz6MAKvX/jYhY7Lq/KfxZGlSPcc4duhisKR+YN7Sooo4xXURNUakzuDqptBZVgjqip7iedAqIlDmwTQsoYW+IVsrDg3T/3SUgAy3CsPcMFEE/S13o/haXa9iHZZl2TEGy7qIY7llUUI33SV/EZ3JBcznnLUqFVKlfjB5pKUlixkl+aMFOTvHUrwWv4UtOs0oczvrFQLihLj34Wqeq9LpN/6lXtVppzcxcAX3JGvmUx1GM4MJA9wXgex/1SXEvwEgkQjd+bSsdPazAV8+1dAqvbPgbyqSJmeCJ1biu/1FaBB4Zni0Dwjl0Rq/IVJ0Z+V8KUgZvQCMQDmRBxKBfkmIR7zlhR66ZYt/FC3L/QDAM6JAKDGh+dURWuI8h75w8OwCItRIEAvm6w8Rjzbxdjb7DOjA/toiyJBgmLOb2ZgkldtpKM+3VrPBzvPl7tSHPK0K01E4z9huIRPw0/3cvaZxMbJshkwcOok33msKRl7MwdWxI3yhIyoElWzNH8RsRl/171PPh/bxWDAd43uX/YfFkY5h0XHvnPUK2BMWFkJps1zLqrA+qFfQAJxHWLDl0keLaCVmpQs0PG+Q+NsXlSqGNSTN/r6Yz4s/qn0A9aJ651iVcnbusdnBmF/sCKPa0WD78nXyD5uFtbZIyzU0xjq6w==",
		},
		// DSA key
		{
			pubKey:      "ssh-dss AAAAB3NzaC1kc3MAAACBANLlxcoOBh5rcRm3b0hg7kN31pFFesd4rAncMPe230bNabgjqCEblZPyCkqP9D4aktKIqiCk43YjreXkDrB/1a1ST0ZjGu4914eGIW68W1vCtqOqFe21kHWLhh/HhZXlWHLwrHu9RkcMOAghDhj/tlkmgu09WfTnJnuXKqrAIYmnAAAAFQCJjFbwiJP976BeSCX3tNLFzR5JHwAAAIEArAdfNtpmnThMD6guamSKg17vv1MtFCxg7xuP7kweFPFepzD+l/xKXsUq1nnTRFqF4HDsHT0xgXY5567wBfQEqATFBxY7Zd/8298TY8aQbLcjLr+pQ9bQRMjKM2XOjVr31neNSJf51DaCjmvNWMv5vnCBoIDXY72TJvSryIN/W9MAAACAFrPrlKRD746a/Qr0+ZOyUI4GJC0e04zgG9a/tLNh6cNyBn6nVVgyCOLhQqONyhZks4ZUFTHphNpEUGBUgN8Ox4kaYf4wQB6G+SvcprjZrC06RCQGJYS5vFSgNpqrh/6nCAaeDtsFH3Lx5ot/sxQYw2OzTOdkbSRCBV/SNBruDNI=",
			expectedErr: unknownKeyTypeError,
		},
		// Small RSA key
		{
			pubKey:      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC5OXmDKEHLVj7nTnYlO5dOdK0BO1XJasLSaz9H+Psj/V3DZeQyJZFkJzyByQXOZa7DN+WEkqaapFb7ttS90Bb+zQ5raeCl3GiRmAH8peHPiOn3Sp5G9QtLFNlYuVswdzYdONX0NTIhF//L7+fmL83fr6WzdnXKL8iSsxSCBKKS5Q==",
			expectedErr: smallRsaKeyError,
		},
	} {
		t.Run(c.pubKey, func(t *testing.T) {
			sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.pubKey))
			require.NoError(t, err)

			err = h.validatePublicKey(sshPubKey)
			require.Equal(t, err, c.expectedErr)
		})
	}
}
