package main

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"net/url"
)

func GetSpnegoToken(cl *client.Client, spn string) (string, error) {
	s := spnego.SPNEGOClient(cl, spn)
	if err := s.AcquireCred(); err != nil {
		return "", err
	}
	st, err := s.InitSecContext()
	if err != nil {
		return "", err
	}
	nb, err := st.Marshal()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nb), nil
}

func GetSPNFromUrl(urlPath string) (string, error) {
	turl, err := url.ParseRequestURI(urlPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", turl.Scheme, turl.Host), nil

}

func SpnegoTokenFromKeytab(kt keytab.Keytab, principal, realm, krb5conf, targetUrl string) (string, error) {
	cfg, err := config.Load(krb5conf)
	if err != nil {
		return "", err
	}
	spn, err := GetSPNFromUrl(targetUrl)
	if err != nil {
		return "", err
	}

	cl := client.NewWithKeytab(principal, realm, &kt, cfg, client.DisablePAFXFAST(true))
	spnegoTicket, err := GetSpnegoToken(cl, spn)
	if err != nil {
		return "", err
	}

	return spnegoTicket, nil
}

func ServiceTicket(cl *client.Client, spn string) (string, error) {
	ticket, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return "", err
	}
	b, err := ticket.Marshal()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
