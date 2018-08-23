package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/miekg/dns"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/net/publicsuffix"
)

type CMS struct {
	Name   string `csv:"name"`
	CName  string `csv:"cname"`
	String string `csv:"string"`
}

type DomainScan struct {
	Domain       string
	Cname        string
	Provider     string
	IsVulnerable bool
	Response     string
}

type Configuration struct {
	domainsFilePath *string
	recordsFilePath *string
	outputFilePath  *string
	domain          *string
	threadCount     *int
	deadRecordCheck *bool
}

func main() {
	config := Configuration{
		domainsFilePath: flag.String("domains", "domains.txt", "List of domains to check"),
		recordsFilePath: flag.String("data", "providers-data.csv", "CSV file containing CMS providers' string for identification"),
		outputFilePath:  flag.String("output", "output.csv", "Output file to save the results"),
		domain:          flag.String("domain", "", "Domains separated by ,"),
		threadCount:     flag.Int("threads", 5, "Number of threads to run parallel"),
		deadRecordCheck: flag.Bool("dead-records", false, "Check for Dead DNS records too")}
	flag.Parse()

	cmsRecords := loadProviders(*config.recordsFilePath)
	var allResults []DomainScan

	if *config.domain != "" {
		for _, domain := range strings.Split(*config.domain, ",") {
			scanResults, err := scanDomain(domain, cmsRecords, config)
			if err == nil {
				allResults = append(allResults, scanResults...)
			}
		}
	} else {
		domainsFile, err := os.Open(*config.domainsFilePath)
		panicOnError(err)
		defer domainsFile.Close()
		domainsScanner := bufio.NewScanner(domainsFile)

		//Create an exec-queue with fixed size for parallel threads, it will block until new element can be added
		//Use this with a waitgroup to wait for threads which will be still executing after we have no elements to add to the queue
		semaphore := make(chan bool, *config.threadCount)
		var wg sync.WaitGroup

		for domainsScanner.Scan() {
			wg.Add(1)
			semaphore <- true
			go func(domain string) {
				scanResults, err := scanDomain(domain, cmsRecords, config)
				if err == nil {
					allResults = append(allResults, scanResults...)
				} /* else {
					fmt.Printf("[%s] Domain problem : %s\n", domain, err)
				}*/
				<-semaphore
				wg.Done()
			}(domainsScanner.Text())
		}
		wg.Wait()
	}

	printResults(allResults)

	if *config.outputFilePath != "" {
		writeResultsToCsv(allResults, *config.outputFilePath)
		Info("Results saved to: " + *config.outputFilePath)
	}
}

//panicOnError function as a generic check for error function
func panicOnError(e error) {
	if e != nil {
		panic(e)
	}
}

//Info function to print pretty output
func Info(format string, args ...interface{}) {
	fmt.Printf("\x1b[34;1m%s\x1b[0m\n", fmt.Sprintf(format, args...))
}

// unFqdn removes the trailing from a FQDN
func unFqdn(domain string) string {
	return strings.TrimSuffix(domain, ".")
}

//scanDomain function to scan for each domain being read from the domains file
func scanDomain(domain string, cmsRecords []*CMS, config Configuration) ([]DomainScan, error) {
	// Check if the domain has a nameserver that returns servfail/refused
	if misbehavingNs, err := authorityReturnRefusedOrServfail(domain); misbehavingNs {
		scanResult := DomainScan{Domain: domain, IsVulnerable: true, Response: "REFUSED/SERVFAIL DNS status"}
		return []DomainScan{scanResult}, nil
	} else if err != nil {
		return nil, err
	}

	cname, err := getCnameForDomain(domain)
	for err != nil && err.Error() == "Recursion detected" {
		cname_old := cname
		cname, err = getCnameForDomain(cname_old)
	}

	if err != nil {
		return nil, err
	}

	// Check if the domain has a dead DNS record, as in it's pointing to a CNAME that doesn't exist
	if *config.deadRecordCheck {
		if exists, err := resolves(cname); !exists {
			scanResult := DomainScan{Domain: domain, Cname: cname, IsVulnerable: true, Response: "Dead DNS record"}
			return []DomainScan{scanResult}, nil
		} else if err != nil {
			return nil, err
		}
	}

	scanResults := checkCnameAgainstProviders(domain, cname, cmsRecords, config)
	if len(scanResults) == 0 {
		err = errors.New(fmt.Sprintf("Cname [%s] found but could not determine provider", cname))
	}
	return scanResults, err
}

// resolves function returns false if NXDOMAIN, and true otherwise
func resolves(domain string) (bool, error) {
	client := dns.Client{}
	message := dns.Msg{}

	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(&message, "1.1.1.1:53")
	if err != nil {
		return false, err
	}
	if r.Rcode == dns.RcodeNameError {
		return false, nil
	}
	return true, nil
}

// getCnameForDomain function to lookup CNAME records of a domain
//
// Doing CNAME lookups using GOLANG's net package or for that matter just doing a host on a domain
// does not necessarily let us know about any dead DNS records. So, we need to read the raw DNS response
// to properly figure out if there are any dead DNS records
func getCnameForDomain(domain string) (string, error) {
	c := dns.Client{}
	m := dns.Msg{}

	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	m.RecursionDesired = true

	r, _, err := c.Exchange(&m, "1.1.1.1:53")
	if err != nil {
		return "", err
	}

	if len(r.Answer) > 0 {
		record := r.Answer[0].(*dns.CNAME)
		cname := record.Target
		return cname, errors.New("Recursion detected")
	} else {
		return domain, nil
	}
	return "", errors.New("Cname not found")
}

// function parseNS to parse NS records (found in answer to NS query or in the authority section) into a list of record values
func parseNS(records []dns.RR) []string {
	var recordData []string
	for _, ans := range records {
		if ans.Header().Rrtype == dns.TypeNS {
			record := ans.(*dns.NS)
			recordData = append(recordData, record.Ns)
		} else if ans.Header().Rrtype == dns.TypeSOA {
			record := ans.(*dns.SOA)
			recordData = append(recordData, record.Ns)
		}
	}
	return recordData
}

// getAuthorityForDomain function to lookup the authoritative nameservers of a domain
func getAuthorityForDomain(domain string, nameserver string) ([]string, error) {
	c := dns.Client{}
	m := dns.Msg{}

	domain = dns.Fqdn(domain)

	m.SetQuestion(domain, dns.TypeNS)
	r, _, err := c.Exchange(&m, nameserver+":53")
	if err != nil {
		return nil, err
	}

	var recordData []string
	if r.Rcode == dns.RcodeSuccess {
		if len(r.Answer) > 0 {
			recordData = parseNS(r.Answer)
		} else {
			// if no NS records are found, fallback to using the authority section
			recordData = parseNS(r.Ns)
		}
	} else {
		return nil, fmt.Errorf("failed to get authoritative servers; Rcode: %d", r.Rcode)
	}

	return recordData, nil
}

// authorityReturnRefusedOrServfail returns true if at least one of the domain's authoritative nameservers
// returns a REFUSED/SERVFAIL response when queried for the domain
func authorityReturnRefusedOrServfail(domain string) (bool, error) {
	// EffectiveTLDPlusOne considers the root domain "." an additional TLD
	// so for "example.com.", it returns "com."
	// but for "example.com" (without trailing "."), it returns "example.com"
	// so we use unFqdn() to remove the trailing dot
	apex, err := publicsuffix.EffectiveTLDPlusOne(unFqdn(domain))
	if err != nil {
		return false, err
	}

	apexAuthority, err := getAuthorityForDomain(apex, "1.1.1.1")
	if err != nil {
		return false, err
	}
	if len(apexAuthority) == 0 {
		return false, fmt.Errorf("couldn't find the apex's nameservers")
	}

	domainAuthority, err := getAuthorityForDomain(domain, apexAuthority[0])
	if err != nil {
		return false, err
	}

	for _, nameserver := range domainAuthority {
		vulnerable, err := nameserverReturnsRefusedOrServfail(domain, nameserver)
		if err != nil {
			// TODO: report this kind of error to the caller?
			continue
		}
		if vulnerable {
			return true, nil
		}
	}
	return false, nil
}

// nameserverReturnsRefusedOrServfail returns true if the given nameserver
// returns a REFUSED/SERVFAIL response when queried for the domain
func nameserverReturnsRefusedOrServfail(domain string, nameserver string) (bool, error) {
	client := dns.Client{}
	message := dns.Msg{}

	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := client.Exchange(&message, nameserver+":53")
	if err != nil {
		return false, err
	}
	if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
		return true, nil
	}
	return false, nil
}

//Now, for each entry in the data providers file, we will check to see if the output
//from the dig command against the current domain matches the CNAME for that data provider
//if it matches the CNAME, we need to now check if it matches the string for that data provider
//So, we curl it and see if it matches. At this point, we know its vulnerable
func checkCnameAgainstProviders(domain string, cname string, cmsRecords []*CMS, config Configuration) []DomainScan {
	transport := &http.Transport{
		Dial:                (&net.Dialer{Timeout: 10 * time.Second}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}}

	client := &http.Client{Transport: transport, Timeout: time.Duration(10 * time.Second)}
	var scanResults []DomainScan

	for _, cmsRecord := range cmsRecords {
		usesprovider, _ := regexp.MatchString(cmsRecord.CName, cname)
		if usesprovider {
			res, str := evaluateDomainProvider(domain, cname, cmsRecord, client, config)
			if res {
				scanResult := DomainScan{Domain: domain, Cname: cname, IsVulnerable: res, Provider: cmsRecord.CName, Response: str}
				scanResults = append(scanResults, scanResult)
			}
		}
	}
	return scanResults
}

//If there is a CNAME and can't curl it, we will assume its vulnerable
//If we can curl it, we will regex match the string obtained in the response with
//the string specified in the data providers file to see if its vulnerable or not
func evaluateDomainProvider(domain string, cname string, cmsRecord *CMS, client *http.Client, config Configuration) (bool, string) {
	httpResponse, err := client.Get(fmt.Sprintf("http://%s", domain))
	httpsResponse, err1 := client.Get(fmt.Sprintf("https://%s", domain))

	if err != nil && err1 != nil {
		if *config.deadRecordCheck {
			return true, "Can't CURL it but dig shows a dead DNS record"
		}
	} else if err == nil && err1 == nil {
		text, err := ioutil.ReadAll(httpResponse.Body)
		text2, err2 := ioutil.ReadAll(httpsResponse.Body)
		if err != nil && err2 != nil {
			return false, err.Error()
		} else {
			x, err := regexp.MatchString(cmsRecord.String, string(text))
			y, err2 := regexp.MatchString(cmsRecord.String, string(text2))
			if err != nil && err2 != nil {
				return false, err.Error()
			}
			if x && y {
				return true, cmsRecord.String
			}
		}
	}
	return false, "nope"
}

func loadProviders(recordsFilePath string) []*CMS {
	clientsFile, err := os.OpenFile(recordsFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	panicOnError(err)
	defer clientsFile.Close()

	cmsRecords := []*CMS{}
	err = gocsv.UnmarshalFile(clientsFile, &cmsRecords)
	panicOnError(err)
	return cmsRecords
}

func writeResultsToCsv(scanResults []DomainScan, outputFilePath string) {
	outputFile, err := os.Create(outputFilePath)
	panicOnError(err)
	defer outputFile.Close()

	err = gocsv.MarshalFile(&scanResults, outputFile)
	panicOnError(err)
}

func printResults(scanResults []DomainScan) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Domain", "Cname", "Provider", "Vulnerable", "Response"})

	for _, scanResult := range scanResults {
		if (len(scanResult.Cname) > 0 && len(scanResult.Provider) > 0) || len(scanResult.Response) > 0 {
			table.Append([]string{scanResult.Domain, scanResult.Cname, scanResult.Provider,
				strconv.FormatBool(scanResult.IsVulnerable),
				scanResult.Response})
		}
	}
	table.Render()
}
