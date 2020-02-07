package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/require"
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
