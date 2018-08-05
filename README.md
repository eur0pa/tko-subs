# tko-subs

This tool allows:
* To check whether a subdomain can be taken over because it has:
	* a dangling CNAME pointing to a CMS provider (Heroku, Github, Shopify, Amazon S3, Amazon CloudFront, etc.) that can be taken over.
	* a dangling CNAME pointing to a non-existent domain name
	* one or more wrong/typoed NS records pointing to a nameserver that can be taken over by an attacker to gain control of the subdomain's DNS records

* To specify your own CMS providers and check for them via the [providers-data.csv](providers-data.csv) file. In that file, you would mention the CMS name, their CNAME value, their string that you want to look for and whether it only works over HTTP or not. Check it out for some examples.


### Disclaimer: DONT BE A JERK!

Needless to mention, please use this tool very very carefully. The authors won't be responsible for any consequences.


### Pre-requisites

We need GO installed. Once you have GO, just type `go get github.com/anshumanbh/tko-subs` to download the tool.

Once the tool is downloaded, type `tko-subs -h`.


### How to run?

Once you have everything installed, `cd` into the directory and type:
`tko-subs -domains=domains.txt -data=providers-data.csv -output=output.csv`

If you just want to check for a single domain, type:
`tko-subs -domain <domain-name>`

If you just want to check for multiple domains, type:
`tko-subs -domain <domain-name-1>,<domain-name-2>`

By default:
* the `domains` flag is set to `domains.txt`
* the `data` flag is set to `providers-data.csv`
* the `output` flag is set to `output.csv`
* the `domain` flag is NOT set so it will always check for all the domains mentioned in the `domains.txt` file. If the `domain` flag is mentioned, it will only check that domain and ignore the `domains.txt` file, even if present
* the `threads` flag is set to `5`

So, simply running `tko-subs` would run with the default values mentioned above.


### How is providers-data.csv formatted?

name,cname,string,http

* name: The name of the provider (e.g. github)
* cname: The CNAME used to map a website to the provider's content (e.g. github.io)
* string: The error message returned for an unclaimed subdomain (e.g. "There isn't a GitHub Pages site here")
* http: Whether to use http (not https, which is the default) to connect to the site (true/false)


### How is the output formatted?

Domain,CNAME,Provider,IsVulnerable,Response

* Domain: The domain checked
* CNAME: The CNAME of the domain
* Provider: The provider the domain was found to be using
* IsVulnerable: Whether the domain was found to be vulnerable or not (true/false)
* Response: The message that the subdomain was checked against

If a dead DNS record is found, `Provider` is left empty.
If a misbehaving nameserver is found, `Provider` and `CNAME` are left empty

### What is going on under the hood?

This will iterate over all the domains (concurrently using GoRoutines) in the `subdomains.txt` file and:
* See if they have a misbehaving authoritative nameserver; if they do, we mark that domain as vulnerable.
* See if they have dangling CNAME records aka dead DNS records; if they do we mark that domain as vulnerable.
* If a subdomain passes these two tests, it tries to curl them and get back a response and then try to see if that response matches any of the data provider strings mentioned in the [providers-data.csv](providers-data.csv) file.
* If the response matches, we mark that domain as vulnerable.
* And, that's it!


### Future Work

* ~Take CMS name and regex from user or .env file and then automatically hook them into the tool to be able to find it.~ DONE
* Add more CMS providers


### Credits

* Thanks to Luke Young (@TheBoredEng) for helping me out with the go-github library.
* Thanks to Frans Rosen (@fransrosen) for helping me understand the technical details that are required for some of the takeovers.
* Thanks to Mohammed Diaa (@mhmdiaa) for taking time to implement the provider data functionality and getting the code going.
* Thanks to high-stakes for a much needed code refresh.


### Changelog
`8/4/18`
* Added more services
* Added CNAME recursion
* Removed takeover functionality

`5/27`
* Added new Dockerfile reducing the size of the image
* Added sample domains.txt file to test against
* mhmdiaa added the logic for dead DNS takeovers. Updated documentation. Thanks a lot!

`11/6`
* high-stakes issues a PR with a bunch of new code that fixes a few bugs and makes the code cleaner

`9/22`
* Added an optional flag to check for single domain
* Made it easier to install and run

`6/25`
* Made the code much more faster by implementing goroutines
* Instead of checking using Golang's net packages' LookupCNAME function, made it to just use dig since that gives you dead DNS records as well. More attack surface!!

