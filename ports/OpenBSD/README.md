# Delphinus DNS
Delphinus DNS is a non-caching, non-recursing DNS server that serves
authoritative answers for A, AAAA, CNAME, DNSKEY, DS, MX, NAPTR, NS,
NSEC3, NSEC3PARAM, PTR, RRSIG, SOA, SRV, SSHFP, TLSA, and TXT resource
records.

For more information please visit Delphinus DNS's [homepage](https://delphinusdns.org).

## Installation

As soon as this port gets imported to OpenBSD, you'll be able to install it with `pkg_add`:

```shell
$ doas pkg_add delphinusdnsd
```

## Thanks

* [Peter J. Philipp](https://delphinusdns.org/credits.html) for developing the software in the first place and for his patience answering all my questions
* [Brian Callahan](https://briancallahan.net) (`bcallah@`) for his awesome [workshop](https://www.youtube.com/watch?v=z_TnemhzbXQ) on how to port software for OpenBSD
* gonzalo for helping with `post-install` instructions
* Pedro Ramos for fixing the rc script
