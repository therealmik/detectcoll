package main

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"github.com/therealmik/detectcoll"
	"github.com/therealmik/x509"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
)

var csv = flag.Bool("csv", false, "Data is in csv format")
var md5 = flag.Bool("md5", false, "Test for md5 collisions instead of sha-1")
var thorough = flag.Bool("thorough", false, "Use extra SHA-1 disturbance vectors")
var csvColumn = flag.Int("column", 1, "CSV column (0 is first)")

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetOutput(os.Stderr)
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("No files specified")
	}

	var wg sync.WaitGroup
	wg.Add(runtime.NumCPU())
	ch := make(chan []byte)

	for i := 0; i < runtime.NumCPU(); i++ {
		go testCertificates(ch, &wg)
	}

	for _, filename := range flag.Args() {
		log.Print("Loading certificates from ", filename)
		if *csv {
			readCsv(filename, ch)
		} else {
			readPem(filename, ch)
		}
	}
	close(ch)
	wg.Wait()
}

func readPem(filename string, ch chan<- []byte) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		ch <- block.Bytes
	}
}

func readCsv(filename string, ch chan<- []byte) {
	fd, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	if *csvColumn < 0 {
		log.Fatal("Invalid CSV column")
	}

	scanner := bufio.NewScanner(fd)
	var lineNumber int
	for scanner.Scan() {
		lineNumber += 1
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) < (*csvColumn - 1) {
			log.Fatalf("Malformed line in %s:%d (should be exactly 1 comma per line), got %v", filename, lineNumber, fields)
		}
		data, err := base64.StdEncoding.DecodeString(fields[*csvColumn])
		if err != nil {
			log.Fatalf("Malformed base64 in %s:%d: %v", filename, lineNumber, err)
		}
		ch <- data
	}
}

func testCertificates(ch <-chan []byte, wg *sync.WaitGroup) {
	var h detectcoll.Hash

	if *md5 {
		h = detectcoll.NewMD5()
	} else {
		if *thorough {
			h = detectcoll.NewSHA1Thorough()
		} else {
			h = detectcoll.NewSHA1()
		}
	}

	for blob := range ch {
		cert, err := x509.ParseCertificate(blob)
		if err != nil {
			// log.Printf("Error in cert %v: %s", err, base64.StdEncoding.EncodeToString(blob))
			continue
		}
		h.Write(cert.RawTBSCertificate)
		if sum, ok := h.DetectSum(nil); !ok {
			log.Printf("Certificate has possible collision (hash=%x)", sum)
			log.Print(base64.StdEncoding.EncodeToString(blob))
		}
		h.Reset()
	}
	wg.Done()
}
