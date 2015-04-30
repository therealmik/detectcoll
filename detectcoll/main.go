package main

import (
	"flag"
	"github.com/therealmik/detectcoll"
	"io"
	"log"
	"os"
	"fmt"
)

var md5 = flag.Bool("md5", false, "Test for md5 collisions")
var sha1 = flag.Bool("sha1", false, "Test for sha-1 collisions")
var thorough = flag.Bool("thorough", false, "Test for extra (unlikely) sha-1 disturbance vectors")

func main() {
	log.SetOutput(os.Stderr)

	var ok bool

	flag.Parse()
	if len(flag.Args()) == 0 {
		ok = checkForCollisions(os.Stdin, "-")
	} else {
		for _, filename := range flag.Args() {
			fd, err := os.Open(filename)
			if err != nil {
				log.Fatalf("Unable to open %s: %v", filename, err)
			}
			ok = checkForCollisions(fd, filename) && ok
		}
	}
	if !ok {
		os.Exit(1)
	}
}

func checkForCollisions(fd io.Reader, filename string) bool {

	if !*md5 && !*sha1 {
		log.Fatal("No hash functions selected - please use -sha1 and/or -md5")
	}

	var md5h, sha1h detectcoll.Hash
	var err error

	if *md5 {
		md5h = detectcoll.NewMD5()
	}
	if *sha1 {
		if *thorough {
			sha1h = detectcoll.NewSHA1Thorough()
		} else {
			sha1h = detectcoll.NewSHA1()
		}
	}

	switch {
	case *md5 && *sha1:
		_, err = io.Copy(sha1h, io.TeeReader(fd, md5h))
	case *md5:
		_, err = io.Copy(md5h, fd)
	case *sha1:
		_, err = io.Copy(sha1h, fd)
	}

	if err != nil {
		log.Fatalf("Unable to read file %s: %v", filename, err)
	}

	var ret bool = true

	if *md5 {
		sum, ok := md5h.DetectSum(nil)
		fmt.Printf("md5(%s): %x\n", filename, sum)
		if !ok {
			log.Printf("MD5 Collision detected in %s!", filename)
		}
		ret = ret && ok
	}

	if *sha1 {
		sum, ok := sha1h.DetectSum(nil)
		fmt.Printf("sha1(%s): %x\n", filename, sum)
		if !ok {
			log.Printf("SHA-1 Collision detected in %s!", filename)
		}
		ret = ret && ok
	}

	return ret
}

