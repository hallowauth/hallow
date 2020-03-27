# Hallow Quickstart

This guide is partially complete. If you are following this guide, please
contribute information on any places where you've gotten stuck and how
to work through that issue.

This document assumes some base level understanding of the moving AWS parts
involved, as well as go. This also assumes `hallow-cli` has been installed,
and can be run on the command line, as well as the ability for your local
computer to talk to the AWS API.

## Push Hallow deployment zip to S3

Pull the latest Hallow zip from [GitHub Actions](https://github.com/hallowauth/hallow/actions?query=branch%3Amaster+event%3Apush), or build your own zip using
`make`, and put that zip in an S3 bucket. When running Terraform, you will
need the bucket name, as well as the name of the file (should be `hallow.zip`).

## Create Hallow in your AWS Environment

First, we need to set up Hallow to run in your AWS environment. This will ask
you where the bucket and file are, as well as which region you're in.

```
cd terraform
terraform apply
```

*This works entirely by accident, for production deployments you'll probably
want to instantiate this as a module.*

In the output of `terraform apply`, you'll get a number of outputs, including
the `ARN` of the `KMS` CA key, and the endpoint.

### Testing `hallow-cli` locally.

Let's see if this all worked! First, take the API endpoint above, and export
that into your environment.

```
# Change the following as required -- be sure us-east-1 is set to your region,
# and your endpoint is set to the right endpoint!

export AWS_REGION=us-east-1
export HALLOW_ENDPOINT=https://UNIQUE_ID.execute-api.REGION.amazonaws.com/prod/hallow
```

If you've never used ssh certificates before, there should be no keys
when you run `ssh-add -L | grep cert`. If there are keys, you likely know
how to debug the following steps on your own. If you don't feel OK debugging
your `ssh-agent`, feel free to continue with the commands and if no breakage
is apparent, assuming things are working until proven otherwise.

If this fails, you may not have Invoke permissions on the API Gateway. You
may need to do debugging to figure out exactly what broke.

```
$ ssh-add -L | grep cert | wc -l
0
$ hallow-cli ssh-add
$ ssh-add -L | grep cert | wc -l
1
```

Great news! Hallow can issue you Certificates! Now let's try it on
a spare computer!

### Get your new CA's Public Key

In the step above, take your AWS KMS ARN (it starts with `arn:aws:kms`), and
invoke `hallow-cli`.

```
$ hallow-cli get-pub-key arn:aws:kms:us-east-1:2........0:key/9fbb4f18-462e-11ea-a661-bfd5f224b840 | tee hallow-ca.pub
```

This will output something like:

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvuBGdFLPNRg+xZkGfQ5u9V3FD6etx0cz0fx6HkjzAvZ0W/FF4HYZPsCkLpsJhjaRfF1Nm9mNXiyaHsrkfaKgQ=
```

That's your CA key! We'll be using that later, so keep that file handy!

### Configure OpenSSH on a test server

Spin up a computer you feel comfortable testing with, and try to configure
your new CA on that computer. Due to the fact we'll be playing with the
ssh daemon configuration, it's very easy to lock yourself out of this
computer, so please be sure it's not important!

#### Get our Principal Name

First, let's figure out who the heck we are. We'll ask AWS who they think
we are, to figure out who Hallow will think we are. Keep a note of this ARN,
this will be used to configure the SSH daemon.

```
$ aws sts get-caller-identity --query="Arn"
"arn:aws:iam::.......:root"
```

#### Remind ourselves of the SSH CA Public Key

We wrote this file out in the step above when we ran `get-pub-key`. Let's get
it in our terminal for later.

```
$ cat hallow-ca.pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvuBGdFLPNRg+xZkGfQ5u9V3FD6etx0cz0fx6HkjzAvZ0W/FF4HYZPsCkLpsJhjaRfF1Nm9mNXiyaHsrkfaKgQ=
```

#### SSH into the target machine

Let's edit the `sshd_config`.

```
$ sudo vim /etc/ssh/sshd_config
```

Append the following lines to the bottom of the `sshd_config`:

```
TrustedUserCAKeys=/etc/ssh/hallow_cas
AuthorizedPrincipalsFile=/etc/ssh/principals/%u
```

Write the key from `hallow-ca.pub` to `/etc/ssh/hallow_cas` on the remote
machine.

```

[user@remote-computer]$ echo "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvuBGdFLPNRg+xZkGfQ5u9V3FD6etx0cz0fx6HkjzAvZ0W/FF4HYZPsCkLpsJhjaRfF1Nm9mNXiyaHsrkfaKgQ=" | sudo tee /etc/ssh/hallow_cas
```

Now, let's write out the AWS ARNs as the authorized principals for any
users we would like to grant access to:

```
[user@remote-computer]$ sudo mkdir /etc/ssh/principals/
[user@remote-computer]$ echo arn::aws::iam::..........:root | sudo tee /etc/ssh/principals/${USER}
```

Finally, let's reboot ssh, and *keep this terminal open!*. If something goes
wrong, your open session can be used to help try and fix things. Open a new
terminal if you can!

```
[user@remote-computer]$ sudo service ssh restart
```

Now, in a **new terminal**, try and `ssh` into the computer, just be sure
the `ssh-agent` still knows about the certificate we just issued!

```
$ ssh -vvv user@remote-computer whoami 2>&1 | grep 'Server accepts key'
debug1: Server accepts key: paultag@nyx ECDSA-CERT SHA256:ISC1x8r1wXbiPDlIgIynjexLJhBdUSvfy/3HCLKAsYI agent
```

Great! The server likes our new CA!

## Add Hallow to ssh/config

`hallow-cli` contains a mode that will allow it to refresh your key
in your running `ssh-agent` when you remote into a computer that matches
a rule.

Open `~/.ssh/config` and add a few lines:

```
Match host remote-computer exec "hallow-cli ssh-add"

Host remote-computer
    HostName ...
    User ...
    ...
```

Now when you ssh into `remote-computer`, `hallow-cli` will refresh your
Certificate if it's required!
