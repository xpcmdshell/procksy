package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"fmt"
	"github.com/elazarl/goproxy"
	"net/http/httputil"
)

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":443", "proxy listen address")
	certPath := flag.String("cert", "cert.crt", "Path to CA certificate")
	keyPath := flag.String("key", "key.pem", "Path to CA key")
	flag.Parse()
	certData, err := ioutil.ReadFile(*certPath)
	if err != nil {
		log.Fatalf("Couldn't read certificate: %v\n", err)
	}
	keyData, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("Couldn't read key: %v\n", err)
	}
	setCA(certData, keyData)
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.Verbose = *verbose
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		requestData, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Printf("Failed to dump request: %v\n", err)
		}
		fmt.Println(string(requestData))
		return req, nil
	})
	log.Fatal(http.ListenAndServe(*addr, proxy))
}