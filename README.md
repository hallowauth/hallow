# Hallow

Hallow is an OpenSSH Certificate Authority tightly coupled to AWS.

## How dos Hallow work?

Hallow uses AWS IAM to authenticate incoming requests via API Gateway to
resolve the IAM identity of the requestee. The API Gateway triggers a Lambda
running Hallow, which will take the AWS IAM User ARN, and sign the provided
SSH Public Key with an asymmetric key (either RSA or ECDSA) stored in KMS.

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
format, seperated by newlines. This file should contain Hallow's KMS
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
| `HALLOW_KMS_KEY_ARN`       | ARN of the KMS asymmetric key |
| `HALLOW_CERT_VALIDITY_DURATION` | Duration that Certifciates issued by Hallow are valid for, in Go `time.Duration` syntax (`1h`, `20s`). Default is `30m` |
| `HALLOW_ALLOWED_KEY_TYPES` | Space delimied list of supported ssh key types (default set is a sensible default of `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-ed25519` |

