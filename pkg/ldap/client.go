package ldap

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

type Client struct {
	Conn     *ldap.Conn
	BaseDN   string
	ConfigDN string
}

func NewClient(server string, port int, useTLS bool, bindDN, password string) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", server, port)
	var conn *ldap.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err = ldap.DialTLS("tcp", addr, tlsConfig)
	} else {
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", addr))
	}

	if err != nil {
		return nil, fmt.Errorf("gagal terhubung ke LDAP server: %w", err)
	}

	if err := conn.Bind(bindDN, password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("gagal otentikasi LDAP (Bind): %w", err)
	}

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "configurationNamingContext"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		conn.Close()
		return nil, fmt.Errorf("gagal membaca RootDSE: %w", err)
	}

	baseDN := res.Entries[0].GetAttributeValue("defaultNamingContext")
	configDN := res.Entries[0].GetAttributeValue("configurationNamingContext")

	return &Client{
		Conn:     conn,
		BaseDN:   baseDN,
		ConfigDN: configDN,
	}, nil
}

func (c *Client) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}
