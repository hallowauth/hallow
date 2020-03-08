# Hallow

Hallow is an OpenSSH Certificate Authority tightly coupled to AWS.

## How does Hallow work?

Hallow uses AWS IAM to authenticate incoming requests via API Gateway to
resolve the IAM identity of the requester. The API Gateway triggers a Lambda
running Hallow, which will take the AWS IAM User ARN, and sign the provided
SSH Public Key with an asymmetric key (currently only ECDSA keys are
supported) stored in KMS.

## Why did we build it?

Our goals in building a new SSH CA were:

- Easy to deploy, even (perhaps especially) for small teams. That's why it has
  relatively few moving pieces, and comes with a terraform module.
- Leverages an existing authentication system. That's why we use AWS IAM for
  authentication, making it trivial to require MFA for SSH.
- Non-extractible private key. That's why we the CA private key lives in KMS.
- Simple to understand. Security tools should make things easier, not more
  complicated. Hallow itself is under 500 lines of code.

## What does it use as the SSH Principal?

Hallow will set the Principal to the User ARN of the incoming request. In
most cases, this means that your User ARN in AWS that was used to hit the
API endpoint will match the principal name in the Certificate.

The only exception is an `sts` `assumed-role` ARN. The Session Name (the last
part of the ARN) is user-controlled, and usually set to something helpful
(like the username of the person assuming the role, or the `i-*` instance ID),
but is not significant, or any assertion of identity. As a result, session
names are removed from `assumed-role` ARNs.

If you are using Assumed Roles, it is important to note that the principal in
your certificate will be of the form
`arn:aws:sts::{account_id}:assumed-role/{role_name}`. It will _not_ be the ARN
for the role itself (which is of the form
`arn:aws:iam::{account_id}:role/{role_name}`).

Additionally, if you are authenticating to Hallow with an Assumed Role, Hallow
will look at the tags on the role, and if there is a tag named
`hallow.additional_principals` it will use that value as additional principals
for the certificate. To pass multiple values comma separate them.

## Deploying Hallow

The easiest way to deploy Hallow is with the Terraform module provided in the
`terraform/` directory. It will deploy all the AWS resources required for
Hallow to work.

For your first deployment try our [quickstart guide](docs/QUICKSTART.md).

## What do I need to do to my system to trust Hallow?

First, the `/etc/ssh/sshd_config` should be updated to add a few flags.
The first is to add the SSH Certificate Authorities, and the second is to
set which principals are allowed for which users on the system.

`TrustedUserCAKeys` is a list of SSH Public Keys in the `authorized_keys`
format, separated by newlines. This file should contain Hallow's KMS
Public Key in SSH format.

`AuthorizedPrincipalsFile` is a list of principals that are allowed to
access the particular user that is being logged into. `%u` means the requested
user, so it's a good idea to keep a directory full of files named after
users of the system. Hallow will set the principal of the Certificate to
the User ARN, so these files should specify the ARNs allowed to access the
particular resources.

### sshd_config

```
TrustedUserCAKeys=/etc/ssh/hallow_cas
AuthorizedPrincipalsFile=/etc/ssh/principals/%u
```

### hallow_cas

Set this file to your own roots. This is an example file, and not the
the one you should put in your own file, unless you want the authors
of this package to have root on your boxes.

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvuBGdFLPNRg+xZkGfQ5u9V3FD6etx0cz0fx6HkjzAvZ0W/FF4HYZPsCkLpsJhjaRfF1Nm9mNXiyaHsrkfaKgQ=
```

### principals/%u

```
arn:aws:iam::12345.....098:root
```

## Configuration knobs

| Environment Variable       | Usage                         |
|----------------------------|-------------------------------|
| `LOG_LEVEL`                | Log Level for Logrus. Valid values are `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` |
| `HALLOW_KMS_KEY_ARN`       | ARN of the KMS asymmetric key. Currently must be an ECDSA key. |
| `HALLOW_CERT_VALIDITY_DURATION` | Duration that Certificates issued by Hallow are valid for, in Go `time.Duration` syntax (`1h`, `20s`). Default is `30m` |
| `HALLOW_ALLOWED_KEY_TYPES` | Space delimited list of supported ssh key types (default set is a sensible default of `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-ed25519` |

## Security considerations

To get the most value out of Hallow, only give people the right to interact
with Hallow via a [role which is assumed with MFA](https://medium.com/starting-up-security/securing-local-aws-credentials-9589b56a0957).
This gets you MFA for SSH.

Generate a fresh private key for every certificate. This reduces the damage
that can be caused by a disclosed private key to the lifetime of the
certificate.

Hallow does not need to be run in the same AWS account as the rest of your
infrastructure.
