package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"serAD/pkg/detectors"
	"serAD/pkg/gatekeeper"
	"serAD/pkg/http"
	"serAD/pkg/ldap"
	"serAD/pkg/reporter"
)

func main() {
	targetIP := flag.String("target", "", "IP Address Target Domain Controller")
	port := flag.Int("port", 389, "Port LDAP / LDAPS (default 389)")
	useTLS := flag.Bool("tls", false, "Gunakan LDAPS (TLS)")
	bindDN := flag.String("user", "", "Username / Bind DN")
	password := flag.String("pass", "", "Password")
	outMD := flag.String("out-md", "audit_report.md", "Nama file laporan Markdown")
	outJSON := flag.String("out-json", "audit_report.json", "Nama file laporan JSON")

	flag.Parse()

	if *targetIP == "" || *bindDN == "" || *password == "" {
		fmt.Println("Penggunaan: go run cmd/serAD/main.go -target <IP> -user <USER> -pass <PASS> [opsi]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("[*] Memulai Pre-Audit Gatekeeper Safety Checks...")
	gk := gatekeeper.New(*targetIP, *port)
	if err := gk.Validate(); err != nil {
		log.Fatalf("[FATAL] Gatekeeper Validation GAGAL: %v", err)
	}
	fmt.Println("[+] Gatekeeper Check PASS: Target valid, privat, dan berada dalam segmen LAN lokal.")

	fmt.Println("[*] Menghubungi LDAP Server...")
	client, err := ldap.NewClient(*targetIP, *port, *useTLS, *bindDN, *password)
	if err != nil {
		log.Fatalf("[FATAL] Koneksi LDAP GAGAL: %v", err)
	}
	defer client.Close()
	fmt.Printf("[+] Terhubung ke LDAP (BaseDN: %s)\n", client.BaseDN)

	fmt.Println("[*] Mengumpulkan data PKI & Active Directory Domain...")
	templates, cas, err := client.HarvestPKI()
	if err != nil {
		log.Printf("[WARN] Gagal mengambil data PKI: %v", err)
	}

	users, computers, err := client.HarvestDomain()
	if err != nil {
		log.Printf("[WARN] Gagal mengambil data Domain Users/Computers: %v", err)
	}

	fmt.Println("[*] Menjalankan HTTP ESC8 Web Enrollment Probe...")
	probe := http.NewProbeClient()
	for i := range cas {
		finding, err := probe.CheckESC8(&cas[i])
		if err != nil {
			log.Printf("[WARN] ESC8 Probe error pada %s: %v", cas[i].DNSHostName, err)
		}
		if finding != nil {
			log.Printf("[!] ESC8 Terdeteksi pada CA %s", cas[i].Name)
		}
	}

	fmt.Println("[*] Mengeksekusi Detection Engine...")
	engine := detectors.NewEngine(users, computers, templates, cas)
	findings := engine.RunAll()

	fmt.Println("[*] Mencetak Laporan...")
	reporter.PrintTerminal(findings)

	if err := reporter.ExportMarkdown(*outMD, findings); err != nil {
		log.Printf("[WARN] Gagal membuat laporan Markdown: %v", err)
	} else {
		fmt.Printf("[+] Laporan Markdown tersimpan: %s\n", *outMD)
	}

	if err := reporter.ExportJSON(*outJSON, findings); err != nil {
		log.Printf("[WARN] Gagal membuat laporan JSON: %v", err)
	} else {
		fmt.Printf("[+] Laporan JSON tersimpan: %s\n", *outJSON)
	}

	fmt.Println("[+] Proses Audit Selesai.")
}
