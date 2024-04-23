---
title: 'attacker.flAWS2.cloud'
date: 2023-01-29
description: 'Writeup for the second installment in the beginner AWS hacking CTF.'
---

This is the second installment in the flAWS.cloud CTF series, [flAWS2.cloud](http://flaws2.cloud/). You can find the first at [flAWS.cloud](https://flaws.cloud).

This CTF has two versions, you can play as an attacker or a defender. I intend to do both, but as the creator suggests, I'm starting with the attacker side. 

I'll link the defender writeup here once I've published it.

## Level 1

For this first level, I'm tasked with finding a non-bruteforceable pin code. Seeing as this is an AWS CTF, I'll begin with doing some AWS enumeration against the scoped domain: `flaws2.cloud`.

![Basic pin input form. It says the pin is too long to bruteforce.](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129154832.png)

I start by checking out `s3.amazonaws.com/level1.flaws2.cloud` and `level1.flaws2.cloud.s3.amazonaws.com`, but both return an access denied response. So, they don't have s3 directory listing enabled for everyone. 

Next, I try `aws s3 ls s3://level1.flaws2.cloud` to see if they have listing enabled for all authenticated aws users. That also results in an access denied.

Inspecting the page source shows that doing a form submission sends the pin to an api endpoint, `https://2rfismmoo8.execute-api.us-east-1.amazonaws.com/default/level1`. I copy the request from my browser's network tab and take it to my command line.

There's a client-side check to validate that user input only has numbers in it, but I want to see how this API reacts to receiving unexpected user input. I submit the request using `curl` and non-numeric payload and the API doesn't react graccefully. 

Instead, it dumps the AWS access key, access key secret, and token. That's convenient!

![Curl request to the aforementioned endpoint with a response that includes a dump of various headers](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129174651.png)

I set up my aws cli with these credentials and am now assuming the role of level1. 

![Output of sts get-caller-identity showing that i am user level1](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129175411.png)

I try to list out the bucket with `aws s3 ls s3://level1.flaws2.cloud` and find the secret endpoint that will take me to the next level.

![The end screen of level 1, has a link to the next level](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129175539.png)

### Lessons Learned 

- Always test API endpoints with unexpected values, they may often react in interesting ways. Developers often dump environment variables or allow verbose stack traces to happen, and sometimes that carries over into production environments.
- The role we got access to was able to list the s3 bucket's contents, which might not have been a necessary permission. Always adhere to the principle of least privilege.
- Input validation can and should occur at multiple steps in a pipeline. As a hacker, you should push against each layer of that input validation.

## Level 2

In this level we're going against some AWS container services. Namely, ECR.

> This next level is running as a container at [http://container.target.flaws2.cloud/](http://container.target.flaws2.cloud/). Just like S3 buckets, other resources on AWS can have open permissions. I'll give you a hint that the ECR (Elastic Container Registry) is named "level2".

Firstly, I navigate to the provided URL and am asked to sign in with HTTP basic auth. 

![http basic auth prompt](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129180254.png)

I try to run `docker pull 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest` to grab the latest container image, but it returns the following error:

`Error response from daemon: Head "https://653711331788.dkr.ecr.us-east-1.amazonaws.com/v2/level2/manifests/latest": no basic auth credentials`

It looks like docker is trying to pull the container through an HTTP request, but that's protected by basic authentication.

There's another way to try to grab the container image, and that's through the AWS CLI. Looking on [HackTricks](https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/aws-services/aws-ecs-ecr-and-eks-enum), I found that I could first enumerate the various digests for the things stored on the container registry. 

```bash
aws ecr batch-get-image --repository-name level2 \
--registry-id 653711331788 \
--image-ids imageTag=latest \
--region us-east-1 | jq '.images[].imageManifest | fromjson'
```

This outputs a list of digests and I start going through each one, looking for sensitive information. 

![Long list of ECR digests in a JSON format](../../../assets/writeups/flaws2.cloud-attacker/Screenshot_2023-01-29_at_19.33.08.png)

This is the command I used to download each layer.

```bash
aws ecr get-download-url-for-layer \ 
    --repository-name level2 \
    --registry-id 653711331788 \
    --layer-digest "sha256:<!--snipped-->" \
    --region us-east-1
```

Eventually, I find one with a `.htm` that contains the address of the next level. I navigate to it, and since it doesn't tell me to go back to level2, I know that I finished this level.

![The level 3 page](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230129193624.png)


### Lessons Learned

- You can enumerate public Elastic Container Registries (ECR), if they're public, as long as you know the account name and the name of the registry. This can sometimes be a difficult ask, but guessing can be effective.

## Level 3

This level instructs that the container endpoint from the previous level is hosting a proxy at `/proxy/`. By navigating to something like [http://container.target.flaws2.cloud/proxy/http://flaws.cloud](http://container.target.flaws2.cloud/proxy/http://flaws.cloud), it will render the `flaws.cloud` URL through the container endpoint.

So, like level 5 of [flaws.cloud](http://flaws.cloud), I can make the server issue requests on my behalf, server-side request forgery (SSRF). This time, however, this ssrf is against a container, rather than an EC2 instance.

The [Hacktricks page for cloud SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf) mentions an endpoint at `http://169.254.170.2/v2/credentials/<GUID>` that will have the IAM credentials for this container. 

To get access to that GUID, I make a proxied request to `file:///proc/self/environ` and it dumps the service's environment variables.

![aforementioned curl request dumping the environment variables](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230130190042.png)

I make a curl request to `http://container.target.flaws2.cloud/proxy/http://169.254.170.2/v2/credentials/2fdf39e7-50cf-4e11-a47a-533525342c80` and it responds with the container's IAM credentials: Access Key, Secret Access Key, and AWS Session Token.

![aforementioned curl request dumping the IAM credentials](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230130190937.png)

I configure a `level3` profile with those credentials and confirm access.

![output of aws sts get-caller-identity showing im authenticated as the container](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230130191114.png)

With this profile, I use `aws s3api list-buckets` to check out the name of the next level.

![list of s3 buckets on the account, has buckets 0-3, and the end bucket sadface](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230130191813.png)

It looks like the only bucket left is for the final level, so I assume that there's more to it. However, when I navigate to the last endpoint, `the-end-962b72bjahfm5b4wcktm8t9z4sapemjb.flaws2.cloud`, I'm greeted by a congratulations screen.

What a bittersweet ending for me, I didn't expect this one to be half the amount of levels as the first! But it was fun, and I appreciate the hard work that went into it. 

Thanks, [Scott](https://twitter.com/0xdabbad00).

![the congratulatory end screen](../../../assets/writeups/flaws2.cloud-attacker/Pasted_image_20230130192042.png)

### Lessons Learned

- If you have SSRF on an ECS instance, you can abuse a metadata instance at `http://169.254.170.2`. The IAM credentials of the service are behind the `/v2/credentials/<GUID>` endpoint, which you can fill out by accessing the service's environment variables. In this instance, a request to `file:///proc/self/environ` was sufficient.
- The [Hacktricks page for cloud SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf) has useful information for SSRF against other cloud services.

