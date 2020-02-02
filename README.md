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

## What do I need to do to my system to trust Hallow?

First, the `/etc/ssh/sshd_config` should be updated to add a few flags.
The first is to add the SSH Certificate Authorities, and the second is to
set which principals are allowed for which users on the system.

```
TrustedUserCAKeys=/path/to/ca-keys
AuthorizedPrincipalsFile=/path/to/user-files/%u
```

`TrustedUserCAKeys` is a list of SSH Public Keys in the `authorized_keys`
format, seperated by newlines. This file should contain Hallow's KMS
Public Key in SSH format.

`AuthorizedPrincipalsFile` is a list of principals that are allowed to
access the particular user that is being logged into. `%u` means the requested
user, so it's a good idea to keep a directory full of files named after
users of the system. Hallow will set the principal of the Certificate to
the User ARN, so these files should specify the ARNs allowed to access the
particular resources.
