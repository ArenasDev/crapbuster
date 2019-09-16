//TODO reuse connection in the same goroutine
package main

import (
  "text/tabwriter"
  "fmt"
  "flag"
  "net/http"
  "os"
  "regexp"
  "bufio"
  "io"
  "sync"
  "strings"
  "strconv"
  "io/ioutil"
  "runtime"
  "time"
  "net/url"
  "crypto/tls"
)

//type for headers and cookies list
type arrayFlags []string

func (i *arrayFlags) String() string {
  return fmt.Sprintf("%s", *i)
}

func (i *arrayFlags) Set(value string) error {
  *i = append(*i, value)
  return nil
}

//vars for params
var (
  host string
  wordlist string
  threads int
  forceGet bool
  ua string
  codes []int
  length int
  w = new(tabwriter.Writer)
  retries int
  errorArray = make(map[string]int)
  verbose bool
  timeout time.Duration
  client http.Client
  proxy string
  method string
  cookiesAux arrayFlags
  cookies []string
  headersAux arrayFlags
  headers []string
  mux sync.Mutex
  requestFile string
  protocol string
  respectBaseURL bool
)

//user agents
const (
  uaChrome string = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19"
  uaFirefox string = "Mozilla/5.0 (Windows; U; Windows NT 5.1; cs; rv:1.9.0.8) Gecko/2009032609 Firefox/3.0.8"
  uaAndroid string = "Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36"
  uaIOS string = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1"
)

func main() {
  checkParams()

  setMethod()

  channel := make(chan string)
  var wg sync.WaitGroup
  printHeader()
  for i := 0; i < threads; i++ {
    go fuzz(channel, &wg)
  }

  loadWordlistIntoChannel(channel)
}

//check params boundaries and process them
func checkParams() {
  var codesAux string
  var codesAuxArray []string
  var timeoutAux int
  validCodes := []int{100,101,102,103,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,306,307,308,
  400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,428,
  429,430,431,440,444,449,450,451,494,495,496,497,499,498,499,500,501,502,503,504,505,506,507,508,509,510,511,520,
  521,522,523,524,525,526,527,530,598}
  flag.StringVar(&host, "h", "", "remote host to fuzz (Only HTTP and HTTPS) (MANDATORY)")
  flag.StringVar(&wordlist, "w", "", "wordlist (MANDATORY)")
  flag.IntVar(&threads, "t", runtime.NumCPU(), "# of threads")
  flag.BoolVar(&forceGet, "f", false, "force GET method")
  flag.StringVar(&ua, "ua", uaFirefox, "User Agent (values: chrome, firefox, android, ios, or custom user agent)")
  flag.StringVar(&codesAux, "c", "200", "HTTP codes to filter by (comma separated HTTP codes)")
  flag.IntVar(&length, "l", -1, "length to filter by (hide results with that length)")
  flag.IntVar(&retries, "r", 1, "number of retries of failed elements")
  flag.BoolVar(&verbose, "v", false, "Verbose")
  flag.IntVar(&timeoutAux, "to", 5, "seconds to wait before timeout (must be greater than 1)")
  flag.StringVar(&proxy, "p", "", "Proxy URL")
  flag.Var(&cookiesAux, "cookies", "Comma separated cookies (\"PHPSESSIONID: frhu374uyd7f8y79u43uy\",\"UserRole: superadmin\")")
  flag.Var(&headersAux, "headers","Comma separated headers (\"X-Secret-Access: true\",\"Authorization Bearer: blabla\")")
  flag.StringVar(&requestFile, "requestfile", "", "HTTP request file to extract host, User-Agent, cookies and headers (has priority over cookies and headers parameters)")
  flag.StringVar(&protocol, "protocol", "", "protocol to use (http or https, only when using requestfile param)")
  flag.BoolVar(&respectBaseURL, "resburl", true, "respect the URL in the request (only when using requestfile param)")
  flag.Parse()

  if threads < 1 {
    fmt.Println("Threads must be greater than 0")
    os.Exit(1)
  }

  if len(wordlist) == 0 {
    fmt.Println("wordlist is mandatory (use -w to specify it)")
    flag.PrintDefaults()
    os.Exit(1)
  }
  
  switch ua {
    case "chrome":
      ua = uaChrome
    case "firefox":
      ua = uaFirefox
    case "android":
      ua = uaAndroid
    case "ios":
      ua = uaIOS
    default:
  }

  codesAuxArray = strings.Split(codesAux,",")
  for _, i := range codesAuxArray {
      j, err := strconv.Atoi(i)
      if err != nil || !contains(validCodes, j) {
        fmt.Println("Codes must be a coma-separated list of valid HTTP codes. Problem with code ", j)
        os.Exit(1)
      }
      codes = append(codes, j)
  }

  if length < -1 {
    fmt.Println("Length must be 0 or more")
    os.Exit(1)
  }

  if retries < 0 {
    fmt.Println("Retries must be 0 or more")
    os.Exit(1)
  }

  if timeoutAux < 1 {
    fmt.Println("Timeout must be greater than 0")
    os.Exit(1)
  }

  if len(requestFile) != 0 {
    extractHTTPParamsFromFile(requestFile)
    protocol = strings.ToLower(protocol)
    if protocol != "http" && protocol != "https" {
      fmt.Println("Protocol is not http or https")
      os.Exit(1)
    }
  } else {
    if len(host) == 0 {
      flag.PrintDefaults()
    }

    matched, _ := regexp.MatchString("https?:\\/\\/(([-a-zA-Z0-9]*)\\.)*([-a-zA-Z0-9])*(:(6553[0-5]|655[0-2]\\d|65[0-4]\\d\\d|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3}|0))?\\/[-a-zA-Z0-9/._]*", host)

    if !matched {
      fmt.Println("Host does not have correct format (http[s]://test.site.com[:443]/[example/test])")
      os.Exit(1)
    }

    /*if host[len(host)-1:] != "/" {
      host += "/"
    }*/

    if len(cookiesAux) > 0 {
      cookies = strings.Split(cookiesAux.String()[1:len(cookiesAux.String())-1],",")
    } else {
      cookies = nil
    }

    if len(headersAux) > 0 {
      headers = strings.Split(headersAux.String()[1:len(headersAux.String())-1],",")
    } else {
      headers = nil
    }
  }

  timeout = time.Duration(time.Duration(timeoutAux) * time.Second)

  transport := &http.Transport{
    MaxIdleConnsPerHost:   threads,
    MaxIdleConns:          100,
    IdleConnTimeout:       5 * time.Second,
    TLSHandshakeTimeout:   5 * time.Second,
  }
  if proxy != "" {
    proxyURL, err := url.Parse(proxy)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }

    transport = &http.Transport{
      Proxy: http.ProxyURL(proxyURL),
      MaxIdleConnsPerHost:   threads,
      MaxIdleConns:          100,
      IdleConnTimeout:       5 * time.Second,
      TLSHandshakeTimeout:   5 * time.Second,
      TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
  }

  client = http.Client{
    Timeout: timeout,
    Transport: transport,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    },
  }
}

func contains(s []int, e int) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

func loadWordlistIntoChannel(channel chan string) {
  file, err := os.Open(wordlist)
  defer file.Close()

  if err != nil {
    fmt.Println(err)
    return
  }

  // Start reading from the file with a reader.
  reader := bufio.NewReader(file)

  var line string
  for {
    line, err = reader.ReadString('\n')
    channel <- host + line[:len(line)-2]
    if err != nil {
      break
    }
  }

  if err != io.EOF {
      fmt.Printf("Failed to read ", wordlist)
  }
}

func fuzz(channel chan string, wg *sync.WaitGroup) {
  for url := range channel {
    req, err := http.NewRequest(method, url, nil)
    if err != nil {
      fmt.Println(err)
      channel <- url
      if (verbose) {
        fmt.Println("Added for retrying:", url)
      }
      errorArray[url] += 1
      return
    }
    // Set headers
    setHeadersAndCookies(req)

    resp, err := client.Do(req)
    if err != nil {
      fmt.Println(err)
      //on error, check number of retries and return value back to channel if necessary
      if errorArray[url] < retries{
        channel <- url
        if (verbose) {
          fmt.Println("Added for retrying:", url)
        }
        errorArray[url] += 1
      }
      return
    }
    defer resp.Body.Close()
    processResult(url, resp)
  }
  wg.Done()
}

func setMethod() {
  //check if server accepts HEAD method
  if forceGet {
    req, err := http.NewRequest("GET", host, nil)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    // Set headers
    setHeadersAndCookies(req)
    _, err = client.Do(req)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    method = "GET"
  } else {
    req, err := http.NewRequest("HEAD", host, nil)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    // Set headers
    setHeadersAndCookies(req)
    resp, err := client.Do(req)
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
    matched, _ := regexp.MatchString("405|501", resp.Status)

    if err != nil || matched {
      req, err := http.NewRequest("GET", host, nil)
      if err != nil {
        fmt.Println(err)
        os.Exit(1)
      }
      // Set headers
      setHeadersAndCookies(req)
      _, err = client.Do(req)
      if err != nil {
        fmt.Println(err)
        os.Exit(1)
      }
      method = "GET"
    }
    method = "HEAD"
  }
}

func setHeadersAndCookies(req *http.Request) {
  // Set headers
  for _, item := range headers {
    if strings.Index(item, ":") == -1 {
      fmt.Println("Problem with the following header:", item)
      os.Exit(1)
    }
    req.Header.Set(item[:strings.Index(item, ":")], item[strings.Index(item, ":")+2:])
  }
 
  // Create and Add cookie to request
  for _, item := range cookies {
    if strings.Index(item, ":") == -1 {
      fmt.Println("Problem with the following cookie:", item)
      os.Exit(1)
    }
    req.AddCookie(&http.Cookie{Name: item[:strings.Index(item, ":")], Value: item[strings.Index(item, ":")+2:]})
  }
}

func printHeader() {
  w.Init(os.Stdout, 0, 6, 1, '\t', 0)
  fmt.Fprintf(w, "%s\t%s\t%s\n", "Status", "Length", "URL")
  w.Flush()
}

func ReadHTTPFromFile(r io.Reader) *http.Request {
  buf := bufio.NewReader(r)
  
  req, err := http.ReadRequest(buf)
  if err != nil {
    fmt.Println("Error obtaining current directory.")
    fmt.Println(err)
    os.Exit(1)
  }

  return req
}

func extractHTTPParamsFromFile(requestFile string) {
  //read file
  input, err := ioutil.ReadFile(requestFile)
  if err != nil {
    fmt.Println(err)
    return
  }

  //create aux file
  dir, err := os.Getwd()
  if err != nil {
    fmt.Println("Error obtaining current directory.")
    fmt.Println(err)
    os.Exit(1)
  }

  file, err1 := os.Create(dir + "aux.txt")
  if err1 != nil {
    fmt.Println("Error creating auxiliary file, do you have enough permissions?")
    fmt.Println(err1)
    os.Exit(1)
  }
  //copy the original file
  
  _, err = file.Write(input)
  if err != nil {
    fmt.Println("Error writing to auxiliary file, do you have enough permissions?")
    fmt.Println(err)
    os.Exit(1)
  }
  
  //open the copy and add two newlines because http.ReadRequest needs them, it does not matter if the file already had them
  file.WriteString("\n\n")
  
  correctedFile, err2 := os.Open(dir + "aux.txt")
  if err != nil {
    fmt.Println(err2)
    return
  }
  
  req := ReadHTTPFromFile(correctedFile)

  //Extract info from the request
  //Method
  forceGet = req.Method == "HEAD"
  
  //Headers
  for key, value := range req.Header {
    if key != "Cookie" {
      headers = append(headers, key + ":" + value[0])  
    } else {
      cookies = strings.Split(value[0],"; ")
    }
  }

  //Host
  host = protocol + "://" + req.Host
  if host[len(host)-1:] != "/" {
    host += "/"
  }
}

func processResult(url string, resp *http.Response) {
  //Code filtering
  var r, _ = strconv.Atoi(resp.Status[:3])
  if contains(codes, r) {
    bodyBytes, err := ioutil.ReadAll(resp.Body)
    mux.Lock()
    if err == nil && method == "GET" && len(bodyBytes) != length {
      if len(bodyBytes) == 1371 {
        fmt.Println(string(bodyBytes))
      }
      fmt.Fprintf(w, "%v\t%v\t%v\n", r, len(bodyBytes), url)
    }
    if err == nil && method == "HEAD" {
      fmt.Fprintf(w, "%v\t%v\t%v\n", r, "-", url)
    }
    w.Flush()
    mux.Unlock()
  }
}