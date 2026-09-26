package gatekeeper

import "testing"

func TestCheckRFC1918(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"10/8", "10.10.10.10", false},
		{"172.16/12", "172.20.1.1", false},
		{"192.168/16", "192.168.1.10", false},
		{"public", "8.8.8.8", true},
		{"invalid", "not-an-ip", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := New(tc.ip, 389)
			err := g.CheckRFC1918()
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckRFC1918(%q) error=%v wantErr=%v", tc.ip, err, tc.wantErr)
			}
		})
	}
}
