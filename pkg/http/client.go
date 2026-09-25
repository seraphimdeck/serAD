package http

import (
	"crypto/tls"
	"net/http"
	"time"
)

type ProbeClient struct {
	HTTPClient *http.Client
}

func NewProbeClient() *ProbeClient {
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &ProbeClient{
		HTTPClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: customTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}
