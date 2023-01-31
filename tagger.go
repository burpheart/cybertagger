package cybertagger

import (
	"bufio"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/ipipdotnet/ipdb-go"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GRule 规则结构体
type GRule struct {
	Product        string      `json:"product"`
	Program        cel.Program `json:"rule"`
	RuleID         string      `json:"rule_id"`
	Level          string      `json:"level"`
	Category       string      `json:"category"`
	ParentCategory string      `json:"parent_category"`
	Softhard       string      `json:"softhard"`
	Company        string      `json:"company"`
	From           string      `json:"from"`
}

// MFinger 指纹识别线程
type MFinger struct {
	ResponseHeader *string
	ResponseBody   *string
	TLSData        string
	Title          *string
	WebServer      *string
	Port           *string
	Banner         string
	Grules         []GRule
	Row            *Result
	sync.Mutex
	isUsed bool
}

//HTTPX结构体

type ChainItem struct {
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
	RequestURL string `json:"request-url,omitempty"`
}
type ZTLSData struct {
	TLSVersion               string   `json:"tls_version,omitempty"`
	CipherSuite              string   `json:"cipher_suite,omitempty"`
	ExtensionServerName      string   `json:"extension_server_name,omitempty"`
	DNSNames                 []string `json:"dns_names,omitempty"`
	Emails                   []string `json:"emails,omitempty"`
	CommonName               []string `json:"common_name,omitempty"`
	Organization             []string `json:"organization,omitempty"`
	IssuerCommonName         []string `json:"issuer_common_name,omitempty"`
	IssuerOrg                []string `json:"issuer_organization,omitempty"`
	FingerprintSHA256        string   `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA256OpenSSL string   `json:"fingerprint_sha256_openssl,omitempty"`
	ClientHello              []byte   `json:"client_hello,omitempty"`
	HandshakeLog             []byte   `json:"handshake_log,omitempty"`
	HeartBleedLog            []byte   `json:"heartbleed_log,omitempty"`
}
type Response struct {
	// Timestamp is the timestamp for certificate response
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Host is the host to make request to
	Host string `json:"host,omitempty"`
	// IP is the IP address the request was made to
	IP string `json:"ip,omitempty"`
	// Port is the port to make request to
	Port string `json:"port,omitempty"`
	// ProbeStatus is false if the tls probe failed
	ProbeStatus bool `json:"probe_status,omitempty"`
	// Error is the optional error for tls request included
	// with errors_json flag.
	Error string `json:"error,omitempty"`
	// Version is the tls version responded by the server
	Version string `json:"tls_version,omitempty"`
	// Cipher is the cipher for the tls request
	Cipher string `json:"cipher,omitempty"`
	// CertificateResponse is the leaf certificate embedded in json
	*CertificateResponse `json:",inline"`
	// TLSConnection is the client used for TLS connection
	// when ran using scan-mode auto.
	TLSConnection string `json:"tls_connection,omitempty"`
	// Chain is the chain of certificates
	//Chain       []*CertificateResponse `json:"chain,omitempty"`
	JarmHash    string   `json:"jarm_hash,omitempty"`
	Ja3Hash     string   `json:"ja3_hash,omitempty"`
	ServerName  string   `json:"sni,omitempty"`
	VersionEnum []string `json:"version_enum,omitempty"`
	//TlsCiphers  []TlsCiphers           `json:"cipher_enum,omitempty"`
	//ClientHello *ztls.ClientHello      `json:"client_hello,omitempty"`
	//ServerHello *ztls.ServerHello      `json:"servers_hello,omitempty"`
}

type CertificateResponse struct {
	// Expired specifies whether the certificate has expired
	Expired bool `json:"expired,omitempty"`
	// SelfSigned returns true if the certificate is self-signed
	SelfSigned bool `json:"self_signed,omitempty"`
	// MisMatched returns true if the certificate is mismatched
	MisMatched bool `json:"mismatched,omitempty"`
	// Revoked returns true if the certificate is revoked
	Revoked bool `json:"revoked,omitempty"`
	// NotBefore is the not-before time for certificate
	NotBefore time.Time `json:"not_before,omitempty"`
	// NotAfter is the not-after time for certificate
	NotAfter time.Time `json:"not_after,omitempty"`
	// SubjectDN is the distinguished name for cert
	SubjectDN string `json:"subject_dn,omitempty"`
	// SubjectCN is the common name for cert
	SubjectCN string `json:"subject_cn,omitempty"`
	// SubjectOrg is the organization for cert subject
	SubjectOrg []string `json:"subject_org,omitempty"`
	// SubjectAN is a list of Subject Alternative Names for the certificate
	SubjectAN []string `json:"subject_an,omitempty"`
	// IssuerDN is the distinguished name for cert
	IssuerDN string `json:"issuer_dn,omitempty"`
	// IssuerCN is the common name for cert
	IssuerCN string `json:"issuer_cn,omitempty"`
	// IssuerOrg is the organization for cert issuer
	IssuerOrg []string `json:"issuer_org,omitempty"`
	// Emails is a list of Emails for the certificate
	Emails []string `json:"emails,omitempty"`
	// FingerprintHash is the hashes for certificate
	FingerprintHash CertificateResponseFingerprintHash `json:"fingerprint_hash,omitempty"`
	// Certificate is the raw certificate in PEM format
	Certificate string `json:"certificate,omitempty"`
	// WildCardCert is true if tls certificate is a wildcard certificate
	WildCardCert bool `json:"wildcard_certificate,omitempty"`
}
type CertificateResponseFingerprintHash struct {
	// MD5 is the md5 hash for certificate
	MD5 string `json:"md5,omitempty"`
	// SHA1 is the sha1 hash for certificate
	SHA1 string `json:"sha1,omitempty"`
	// SHA256 is the sha256 hash for certificate
	SHA256 string `json:"sha256,omitempty"`
}
type AsnResponse struct {
	AsNumber  string   `json:"as_number" csv:"as_number"`
	AsName    string   `json:"as_name" csv:"as_name"`
	AsCountry string   `json:"as_country" csv:"as_country"`
	AsRange   []string `json:"as_range" csv:"as_range"`
}
type CSPData struct {
	Domains []string `json:"domains,omitempty"`
}

type Result struct {
	Timestamp          time.Time              `json:"timestamp,omitempty" csv:"timestamp"`
	ASN                *AsnResponse           `json:"asn,omitempty" csv:"asn"`
	CSPData            *CSPData               `json:"csp,omitempty" csv:"csp"`
	TLSData            Response               `json:"tls,omitempty" csv:"tls"`
	Hashes             map[string]interface{} `json:"hash,omitempty" csv:"hash"`
	ExtractRegex       []string               `json:"extract_regex,omitempty" csv:"extract_regex"`
	CDNName            string                 `json:"cdn_name,omitempty" csv:"cdn_name"`
	Port               string                 `json:"port,omitempty" csv:"port"`
	URL                string                 `json:"url,omitempty" csv:"url"`
	Input              string                 `json:"input,omitempty" csv:"input"`
	Location           string                 `json:"location,omitempty" csv:"location"`
	Title              string                 `json:"title,omitempty" csv:"title"`
	Ip                 string                 `json:"ip,omitempty" csv:"ip"`
	Scheme             string                 `json:"scheme,omitempty" csv:"scheme"`
	Error              string                 `json:"error,omitempty" csv:"error"`
	WebServer          string                 `json:"webserver,omitempty" csv:"webserver"`
	ResponseBody       string                 `json:"body,omitempty" csv:"body"`
	ContentType        string                 `json:"content_type,omitempty" csv:"content_type"`
	Method             string                 `json:"method,omitempty" csv:"method"`
	Host               string                 `json:"host,omitempty" csv:"host"`
	Path               string                 `json:"path,omitempty" csv:"path"`
	FavIconMMH3        string                 `json:"favicon,omitempty" csv:"favicon"`
	FaviconPath        string                 `json:"favicon_path,omitempty" csv:"favicon_path"`
	FinalURL           string                 `json:"final_url,omitempty" csv:"final_url"`
	ResponseHeader     map[string]interface{} `json:"header,omitempty" csv:"header"`
	RawHeader          string                 `json:"raw_header,omitempty" csv:"raw_header"`
	Request            string                 `json:"request,omitempty" csv:"request"`
	ResponseTime       string                 `json:"time,omitempty" csv:"time"`
	Jarm               string                 `json:"jarm,omitempty" csv:"jarm"`
	ChainStatusCodes   []int                  `json:"chain_status_codes,omitempty" csv:"chain_status_codes"`
	A                  []string               `json:"a,omitempty" csv:"a"`
	CNAMEs             []string               `json:"cname,omitempty" csv:"cname"`
	Technologies       []string               `json:"tech,omitempty" csv:"tech"`
	Extracts           map[string][]string    `json:"extracts,omitempty" csv:"extracts"`
	Chain              []ChainItem            `json:"chain,omitempty" csv:"chain"`
	Words              int                    `json:"words" csv:"words"`
	Lines              int                    `json:"lines" csv:"lines"`
	StatusCode         int                    `json:"status_code,omitempty" csv:"status_code"`
	ContentLength      int                    `json:"content_length,omitempty" csv:"content_length"`
	Failed             bool                   `json:"failed" csv:"failed"`
	VHost              bool                   `json:"vhost,omitempty" csv:"vhost"`
	WebSocket          bool                   `json:"websocket,omitempty" csv:"websocket"`
	CDN                bool                   `json:"cdn,omitempty" csv:"cdn"`
	HTTP2              bool                   `json:"http2,omitempty" csv:"http2"`
	Pipeline           bool                   `json:"pipeline,omitempty" csv:"pipeline"`
	StoredResponsePath string                 `json:"stored_response_path,omitempty" csv:"stored_response_path"`
	Country            string                 `json:"country,omitempty" csv:"country"`
	Province           string                 `json:"province,omitempty" csv:"province"`
	City               string                 `json:"city,omitempty" csv:"city"`
	TaskId             string                 `json:"task_id,omitempty" csv:"task_id"`
	Tag                []string               `json:"tag,omitempty" csv:"tag"`
	Finger             []string               `json:"finger,omitempty" csv:"finger"`
}

var InputLines uint64 = 0
var OutLines uint64 = 0
var LastOutLines uint64 = 0

func RunNew(finger bool, src string, dst string, taskid string) {
	timeTickerChan := time.Tick(time.Second * 1)
	//TODO 不知道为什么丟数据 结尾部分数据行丢失  丢失数量差不多和线程数一样
	//多线程  非常消耗内存 6000条规则 一个线程至少占用160M内存 可以跑满cpu
	var mu sync.Mutex
	var maxGoroutines = runtime.NumCPU() //最大线程设置为CPU核心数  限制CPU资源的docker容器中判断会有问题
	var ch = make(chan bool, maxGoroutines)
	//finger = true
	var mf []*MFinger
	for i := 0; i < maxGoroutines; i++ {
		var f MFinger //为了提升性能使用预先分配的指纹线程  避免使用go-cel设置变量
		f.Init()
		mf = append(mf, &f)
	}
	fmt.Printf("成功解析%d条规则\n", len(mf[0].Grules))
	go func() {
		for {
			tempnum := atomic.LoadUint64(&OutLines)
			io.WriteString(os.Stderr, fmt.Sprintf("Input: %d Out: %d %6.3d/s       \r", InputLines, OutLines, (tempnum-LastOutLines)/1))
			LastOutLines = tempnum
			<-timeTickerChan
		}
	}()
	f, _ := os.OpenFile(dst, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	db, err := ipdb.NewCity("ipip.ipdb") // 使用 IPIP数据库 https://www.ipip.net/free_download/
	if err != nil {
		log.Fatal(err)
	}
	file, _ := os.Open(src)
	//const maxCapacity = 1024 * 1024 * 10 //限制单行10M
	//buf := make([]byte, maxCapacity)
	//input := bufio.NewScanner(file)
	//input.Buffer(buf, maxCapacity)

	jsonEncoder := json.NewEncoder(f)
	input := bufio.NewReader(file)
	//const Capacity = 1024 * 1024 * 10 //默认10M空间
	//linebuf := make([]byte, Capacity)
	var linebuf string
	for {
		//s := input.Bytes()
		s, err := input.ReadString('\n')
		if err != nil {
			if err == bufio.ErrBufferFull {
				linebuf = linebuf + s
				continue
			}
			if err == io.EOF {
				break
			}
			log.Fatalf(err.Error())
		}
		if len(linebuf) > 0 {
			s = linebuf + s
			linebuf = ""
		}
		ch <- true
		go func(s string) {
			atomic.AddUint64(&InputLines, 1)
			defer func() { <-ch }()
			var row Result
			err := json.Unmarshal([]byte(s), &row)

			if err != nil {
				fmt.Println("DecodeErr:", string(s), err)
				return
			}
			if row.Failed {
				return
			}
			a, err := db.Find(row.Host, "CN")
			if err != nil {
				fmt.Println("IPDbErr:", row.Host)
				row.Country = "未知"
			}
			switch len(a) {
			case 3:
				row.Country = a[0]
				row.Province = a[1]
				row.City = a[2]
			case 2:
				row.Country = a[0]
				row.Province = a[1]
			case 1:
				row.Country = a[0]
			}
			row.Ip = row.Host
			if finger {
				for {
					ok := false
					for _, s := range mf {
						s.Lock()
						if !s.isUsed {
							s.isUsed = true
							s.Unlock()
							s.ResponseHeader = &row.RawHeader //不要拷贝
							s.ResponseBody = &row.ResponseBody
							s.TLSData = fmt.Sprintf("%v", row.TLSData)
							s.Title = &row.Title
							s.Port = &row.Port
							s.WebServer = &row.WebServer
							s.Row = &row
							s.Do()
							s.Lock()
							s.isUsed = false
							s.Unlock()
							ok = true
							break
						}
						s.Unlock()
					}
					if ok {
						break
					}

				}
			}
			row.TaskId = taskid
			mu.Lock()
			defer mu.Unlock()
			err = jsonEncoder.Encode(row)
			if err != nil {
				fmt.Println("EncodeErr: ", err)
			} //Encoder  线程不安全 需要加锁
			atomic.AddUint64(&OutLines, 1)
		}(s[:len(s)-1])

	}

}

func (f *MFinger) Do() {
	for _, v := range f.Grules {

		out, _, err := v.Program.Eval(map[string]any{})
		//v.Program.ContextEval()
		if err != nil {
			log.Fatalf("Evaluation error: %v\n", err)
		}
		if out.Value().(bool) {
			f.Row.Finger = append(f.Row.Finger, v.Product)
		}
	}

}

// Init 初始化指纹规则
func (f *MFinger) Init() {

	if len(f.Grules) > 0 {
		return
	}
	type Rule struct {
		Product        string `json:"product"`
		Rule           string `json:"rule"`
		RuleID         string `json:"rule_id"`
		Level          string `json:"level"`
		Category       string `json:"category"`
		ParentCategory string `json:"parent_category"`
		Softhard       string `json:"softhard"`
		Company        string `json:"company"`
		From           string `json:"from"`
	}

	env, err := cel.NewEnv(
		cel.Function("banner_contain",
			cel.Overload("banner_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(strings.Contains(*f.ResponseHeader, lhs.Value().(string)) || strings.Contains(*f.ResponseBody, lhs.Value().(string)))
				},
				),
			),
		),
		cel.Function("banner_equal",
			cel.Overload("banner_equal_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(false) //没实现 非WEB应用
					//return types.Bool("%s are shaking hands." == lhs.Value().(string))
				},
				),
			),
		),
		cel.Function("body_contain",
			cel.Overload("body_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(strings.Contains(*f.ResponseBody, lhs.Value().(string)))
				},
				),
			),
		),
		cel.Function("body_equal",
			cel.Overload("body_equal_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(*f.ResponseBody == lhs.Value().(string))
				},
				),
			),
		),
		cel.Function("cert_contain",
			cel.Overload("cert_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {

					return types.Bool(strings.Contains(fmt.Sprintf("%v", f.TLSData), lhs.Value().(string)))
				},
				),
			),
		),
		cel.Function("header_contain",
			cel.Overload("header_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(strings.Contains(*f.ResponseHeader, lhs.Value().(string)))
				},
				),
			),
		),
		cel.Function("server_contain",
			cel.Overload("server_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(strings.Contains(*f.WebServer, lhs.Value().(string)))
				},
				),
			),
		),
		cel.Function("server_equal",
			cel.Overload("server_equal_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(*f.WebServer == lhs.Value().(string))
				},
				),
			),
		),
		cel.Function("protocol_contain",
			cel.Overload("protocol_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(false) //没实现
					//return types.Bool(strings.Contains(row.WebServer, lhs.Value().(string)))
				},
				),
			),
		), cel.Function("title_contain",
			cel.Overload("title_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(strings.Contains(*f.Title, lhs.Value().(string)))
				},
				),
			),
		), cel.Function("title_equal",
			cel.Overload("title_equal_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(*f.Title == lhs.Value().(string))
				},
				),
			),
		), cel.Function("port_contain",
			cel.Overload("port_contain_string_bool",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					return types.Bool(*f.Port == lhs.Value().(string))
				},
				),
			),
		),
	)
	if err != nil {
		log.Fatalf("environment creation error: %v\n", err)
	}
	// Check iss for error in both Parse and Check.
	//file, _ := os.Open("finger.json")
	file, _ := os.Open("finger.json")
	//const maxCapacity = 1024 * 1024 * 10
	//buf := make([]byte, maxCapacity)
	input := bufio.NewScanner(file)
	//input.Buffer(buf, maxCapacity)
	for input.Scan() {
		s := input.Bytes()
		var rule Rule
		err := json.Unmarshal(s, &rule)
		if err != nil {
			fmt.Println("FingerDecodeErr:", string(s), err)
		}
		ast, iss := env.Compile(rule.Rule)
		if iss.Err() != nil {
			//fmt.Println("FingerCompileErr:", string(s), iss.Err().Error())
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			log.Fatalf("Program creation error: %v\n", err)
		}
		var grule GRule
		grule.Product = rule.Product
		grule.Company = rule.Company
		grule.From = rule.From
		grule.Level = rule.Level
		grule.ParentCategory = rule.ParentCategory
		grule.RuleID = rule.RuleID
		grule.Softhard = rule.Softhard
		grule.Program = prg
		f.Grules = append(f.Grules, grule)
	}
}
