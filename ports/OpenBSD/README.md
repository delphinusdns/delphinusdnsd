## Build and installation

```shell
cp -R ports/OpenBSD/delphinusdnsd /usr/ports/mystuff/net
cd /usr/ports/mystuff/net/delphinusdnsd
make makesum
make build
make package
make install
```

## Thanks

* [Peter J. Philipp](https://delphinusdns.org/credits.html) for developing the software in the first place and for his patience answering all my questions
* [Brian Callahan](https://briancallahan.net) (`bcallah@`) for his awesome [workshop](https://www.youtube.com/watch?v=z_TnemhzbXQ) on how to port software for OpenBSD
* gonzalo for helping with `post-install` instructions
* ajacoutot@ for fixing the rc script
