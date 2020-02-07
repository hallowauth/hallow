# Installing SAM (Severless Application Model)

AWS SAM allows you to test Lambdas locally using Docker and some Python
glue.

This guide assumes you have `docker` set up and working.

## Create a virtualenv

If you have `virtualenvwrapper` installed, run:

```
mkvirtualenv --python=$(which python3) sam
pip install aws-sam-cli
```

# Using SAM

Set your `HALLOW_KMS_KEY_ARN` in `template.yaml`

```
sam local invoke "Hallow" -e test-event.json | jq -r .body | ssh-keygen -f - -L
```
