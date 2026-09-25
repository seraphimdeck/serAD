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

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

const Banner = `
 ██████╗███████╗██████╗  █████╗ ██████╗ 
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗
███████╗█████╗  ██████╔╝███████║██║  ██║
╚════██║██╔══╝  ██╔══██╗██╔══██║██║  ██║
███████║███████╗██║  ██║██║  ██║██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  v1.0.0
 Active Directory & AD CS Audit Engine
`

func main() {
	targetIP := flag.String("target", "", "IP Address Target Domain Controller")
	port := flag.Int("port", 389, "Port LDAP / LDAPS (default 389)")
	useTLS := flag.Bool("tls", false, "Gunakan LDAPS (TLS)")
	bindDN := flag.String("user", "", "Username / Bind DN")
	password := flag.String("pass", "", "Password")
	outMD := flag.String("out-md", "audit_report.md", "Nama file laporan Markdown")
	outJSON := flag.String("out-json", "audit_report.json", "Nama file laporan JSON")

	flag.Usage = func() {
		fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)
		fmt.Printf("%sPenggunaan:%s ./serAD -target <IP> -user <USER> -pass <PASS> [opsi]\n\n", Bold+Yellow, Reset)
		fmt.Printf("%sOpsi Parameter:%s\n", Bold, Reset)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *targetIP == "" || *bindDN == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("%s%s%s\n", Cyan, Banner, Reset)

	fmt.Printf("%s[*] Memulai Pre-Audit Gatekeeper Safety Checks...%s\n", Bold+Blue, Reset)
	gk := gatekeeper.New(*targetIP, *port)
	if err := gk.Validate(); err != nil {
		log.Fatalf("%s[FATAL] Gatekeeper Validation GAGAL: %v%s", Bold+Red, err, Reset)
	}
	fmt.Printf("%s[+] Gatekeeper Check PASS: Target valid, privat, dan berada dalam segmen LAN lokal.%s\n", Green, Reset)

	fmt.Printf("%s[*] Menghubungi LDAP Server...%s\n", Bold+Blue, Reset)
	client, err := ldap.NewClient(*targetIP, *port, *useTLS, *bindDN, *password)
	if err != nil {
		log.Fatalf("%s[FATAL] Koneksi LDAP GAGAL: %v%s", Bold+Red, err, Reset)
	}
	defer client.Close()
	fmt.Printf("%s[+] Terhubung ke LDAP (BaseDN: %s)%s\n", Green, client.BaseDN, Reset)

	fmt.Printf("%s[*] Mengumpulkan data PKI & Active Directory Domain...%s\n", Bold+Blue, Reset)
	templates, cas, err := client.HarvestPKI()
	if err != nil {
		log.Printf("%s[WARN] Gagal mengambil data PKI: %v%s", Yellow, err, Reset)
	}

	users, computers, err := client.HarvestDomain()
	if err != nil {
		log.Printf("%s[WARN] Gagal mengambil data Domain Users/Computers: %v%s", Yellow, err, Reset)
	}

	fmt.Printf("%s[*] Menjalankan HTTP ESC8 Web Enrollment Probe...%s\n", Bold+Blue, Reset)
	probe := http.NewProbeClient()
	for i := range cas {
		finding, err := probe.CheckESC8(&cas[i])
		if err != nil {
			log.Printf("%s[WARN] ESC8 Probe error pada %s: %v%s", Yellow, cas[i].DNSHostName, err, Reset)
		}
		if finding != nil {
			log.Printf("%s[!] ESC8 Terdeteksi pada CA %s%s", Bold+Red, cas[i].Name, Reset)
		}
	}

	fmt.Printf("%s[*] Mengeksekusi Detection Engine...%s\n", Bold+Blue, Reset)
	engine := detectors.NewEngine(users, computers, templates, cas)
	findings := engine.RunAll()

	fmt.Printf("%s[*] Mencetak Laporan...%s\n", Bold+Blue, Reset)
	reporter.PrintTerminal(findings)

	if err := reporter.ExportMarkdown(*outMD, findings); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan Markdown: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan Markdown tersimpan: %s%s\n", Green, *outMD, Reset)
	}

	if err := reporter.ExportJSON(*outJSON, findings); err != nil {
		log.Printf("%s[WARN] Gagal membuat laporan JSON: %v%s", Yellow, err, Reset)
	} else {
		fmt.Printf("%s[+] Laporan JSON tersimpan: %s%s\n", Green, *outJSON, Reset)
	}

	fmt.Printf("%s[+] Proses Audit Selesai.%s\n", Bold+Green, Reset)
}
