# DetectColl
This is an implementation of Marc Stevens' [Counter Cryptanalysis](https://marc-stevens.nl/research/papers/C13-S.pdf) in Go

It implements the hash.Hash interface, as well as a new detectcoll.Hash interface, which adds the method:
```go
hashBytes, ok := h.DetectSum(appendTo)
```
You can also import `github.com/therealmik/detectcoll/sha1` and `github.com/therealmik/detectcoll/md5`
to register the hashes with the crypto subsystem, and they'll log with the golang `log` package if a collision attempt
is detected.

There is a C version written by Marc Stevens and plenty of great hash breaking resources at [his website](https://marc-stevens.nl/research/).

To install:
```
go get -u github.com/therealmik/detectcoll
go get -u github.com/therealmik/detectcoll/...
```
