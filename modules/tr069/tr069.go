package tr069

/* 

CPE(Client)                                      ACS(Server)
	| ----------------------GET---------------------->|
	|                                                 |
	|<----------------------Banner--------------------| // This is collected in get_response

if GET returned 200 OK or 405 Method Not Allowed -> it's possible to communicate via CWMP

   	|                                                 |
    	|--------------- (1) Open connection ------------>|
	|                                                 | 
	|--------------- (2) HTTP POST (Inform) --------->|
	|                                                 |	
    	|<-------------- (3) HTTP 200 OK (InformResp) ----| // This is collected in inform_response
    	|                                                 |
    	|--------------- (4) HTTP POST (empty) ---------->| 
	|                                                 |	
    	|<-------------- (5) HTTP 200 OK (GetParam) ------| // This is collected in post_response

*/

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Result struct {
	Observed       string `json:"observed"`
	IP             string `json:"ip"`
	Port           uint   `json:"port"`
	Server         string `json:"server,omitempty"`
	WwwAuth        string `json:"www_authenticate,omitempty"`
	HTTPVersion    string `json:"http_version,omitempty"`
	Status         string `json:"status,omitempty"`
	GetResponse    string `json:"get_response,omitempty"`
	InformResponse string `json:"inform_response,omitempty"`
	PostResponse   string `json:"post_response,omitempty"`
}

const (
	PERMANENT_STATUS_OK = iota
	INFORM_STATUS_OK
	INFORM_METHOD_NOT_ALLOWED
	INFORM_STATUS_FAILED
	INFORM_STATUS_UNKNOWN
	BAD_INFORM_REQUEST
)

var cwmpPattern = regexp.MustCompile(`(?i)(cwmp|tr[^a-zA-Z0-9]*069|tr069|gsoap|genieacs|\b(cpe|acs)\b)`)

/*
	This function sends an Inform request and collects results in result
	Upon successful execution, an empty POST request is sent
*/
func doTR069InformSequence(ctx context.Context, addr string, result *Result) int {

	client := &http.Client{Timeout: 3 * time.Second}

	inform_msg, err := generateInformXML()
	if err != nil {
		log.Errorf("Failed to generate Inform XML: %v", err)
		return BAD_INFORM_REQUEST
	}

	/* Inform request */
	inform_req, err := http.NewRequestWithContext(ctx, "POST", addr, strings.NewReader(inform_msg))
	if err != nil {
		log.Errorf("Failed to create POST/Inform: %v", err)
		return BAD_INFORM_REQUEST
	}

	inform_req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	inform_req.Header.Set("SOAPAction", `\"urn:dslforum-org:cwmp-Inform\"`)

	inform_resp, err := client.Do(inform_req)
	if err != nil {
		log.Warnf("POST/Inform failed: %v", err)
		return INFORM_STATUS_FAILED
	}
	defer inform_resp.Body.Close()

	inform_resp_status := inform_resp.StatusCode
	inform_resp_raw, _ := io.ReadAll(inform_resp.Body)
	inform_resp_body := strings.TrimSpace(string(inform_resp_raw))

	inform_resp_is_valid := isValidCWMPEnvelope(inform_resp_body)

	/* If Inform response is not valid -> return error */
	if !(inform_resp_status == 200 && inform_resp_is_valid) {
		log.Warnf("POST/Inform did not return valid CWMP SOAP Envelope: status=%d, empty=%t", inform_resp_status, inform_resp_is_valid)

		if inform_resp_status/100 == 5 {
			return INFORM_METHOD_NOT_ALLOWED
		}
		if inform_resp_status/100 == 2 {
			return PERMANENT_STATUS_OK
		}

		return INFORM_STATUS_UNKNOWN
	}

	log.Infof("POST/Inform returned valid CWMP SOAP Envelope: status=%d", inform_resp_status)

	result.InformResponse = inform_resp_body // collect result

	/* If Inform response is valid -> send empty POST */
	empty_req, err := http.NewRequestWithContext(ctx, "POST", addr, nil)
	if err != nil {
		log.Errorf("Failed to create POST/Empty: %v", err)
		return INFORM_STATUS_OK
	}

	var session_cookie string
	for _, c := range inform_resp.Cookies() {
		if c.Name == "session" {
			session_cookie = c.Value
			break
		}
	}

	empty_req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	empty_req.Header.Set("SOAPAction", `""`)
	if session_cookie != "" {
		empty_req.AddCookie(&http.Cookie{Name: "session", Value: session_cookie})
	}

	empty_resp, err := client.Do(empty_req)
	if err != nil {
		log.Warnf("Empty POST failed: %v", err)
		return INFORM_STATUS_OK
	}
	defer empty_resp.Body.Close()

	empty_resp_raw, _ := io.ReadAll(empty_resp.Body)
	result.PostResponse = strings.TrimSpace(string(empty_resp_raw)) // collect result

	return INFORM_STATUS_OK
}

/*
	Main function that is called from scanner.go
	Sends GET request and collects results in result
	If possible, sends Inform request and collects results in result
*/
func GetTR069Banner(ctx context.Context, dialer *zgrab2.DialerGroup, target *zgrab2.ScanTarget, config *Flags) (zgrab2.ScanStatus, any, error) {
	addr := fmt.Sprintf("http://%s:%d", target.Host(), target.Port)
	client := &http.Client{Timeout: 3 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", addr, nil)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer resp.Body.Close()

	raw_body, _ := io.ReadAll(resp.Body)

	result := Result{
		Observed:    time.Now().UTC().String(),
		IP:          target.Host(),
		Port:        target.Port,
		Server:      resp.Header.Get("Server"),
		WwwAuth:     resp.Header.Get("Www-Authenticate"),
		HTTPVersion: resp.Proto,
		Status:      resp.Status,
		GetResponse: strings.TrimSpace(string(raw_body)),
	}

	inform_status := INFORM_STATUS_UNKNOWN

	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusOK {
		inform_status = doTR069InformSequence(ctx, addr, &result)
	}

	if config.Forecast {
		scoreTR069(resp.Header, int(target.Port), resp.StatusCode, len(result.PostResponse) == 0, inform_status)
	}

	return zgrab2.SCAN_SUCCESS, &result, nil
}

/*
	Function calculates scores for CWMP based on the received data
	Simple heuristic that looks for keywords and signs of CWMP
*/
func scoreTR069(headers http.Header, port int, get_status int, get_body_empty bool, inform_status int) {
	if inform_status == BAD_INFORM_REQUEST {return}

	var (
		score             int
		head_server       string = headers.Get("Server")
		head_www_auth     string = headers.Get("Www-Authenticate")
		head_content_type string = headers.Get("Content-Type")
	)

	switch inform_status {
	case INFORM_STATUS_OK:
		score += 5
	case INFORM_STATUS_FAILED:
		score -= 3
	case INFORM_METHOD_NOT_ALLOWED:
		score -= 5
	case PERMANENT_STATUS_OK:
		if get_body_empty {
			score -= 3
		}
	}

	if head_server != "" && cwmpPattern.MatchString(head_server) {score += 4}

	if head_www_auth != "" && cwmpPattern.MatchString(head_www_auth) {score += 4}

	if strings.Contains(head_content_type, "xml") ||
		strings.Contains(head_content_type, "soap") {score += 1}

	if port == 7547 {
		if strings.Contains(head_www_auth, "HuaweiHomeGateway") ||
			strings.Contains(head_www_auth, "T3BhcXVlIHN0cmluZyBmb3IgQUNTIEF1dGhlbnRpY2F0aW9u") { /* Opaque string for ACS Authentication */
			score += 3
		} else {
			score += 2
		}
	}

	switch {
	case score >= 4:
		log.Infof("\033[32m•It looks like this device communicates using CWMP. (score=%d)\033[0m\n", score)
	case score >= 2:
		log.Infof("\033[33m•Uncertain — could be CWMP, but more evidence is needed. (score=%d)\033[0m\n", score)
	default:
		log.Infof("\033[31m•It doesn't look like this device communicates using CWMP. (score=%d)\033[0m\n", score)
	}

}
