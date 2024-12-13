package servex

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/maxbolgarin/lang"
)

// MakeRawRequest makes a raw HTTP request in a form of []byte.
func MakeRawRequest(path, host string, headers map[string]string, body ...string) []byte {
	// Cannot use plain string because rune '\n' becomes string "\\n"
	// and readBuff.ReadSlice('\n') won't work properly inside net/http readRequest().
	req := make([]byte, 0, 1024)

	req = append(req, ("GET " + lang.Check(path, "/") + " HTTP/1.1")...)
	req = append(req, '\n')
	req = append(req, ("Host: " + lang.Check(host, "example.com:80"))...)

	return append(req, headersAndBody(headers, body)...)
}

// MakeRawResponse makes a raw HTTP response in a form of []byte.
func MakeRawResponse(code int, headers map[string]string, body ...string) []byte {
	code = lang.Check(code, http.StatusOK)

	// Cannot use here plain string because rune '\n' becomes string "\\n"
	// and readBuff.ReadSlice('\n') won't work properly inside net/http readRequest().
	req := make([]byte, 0, 128)
	req = append(req, ("HTTP/1.1 " + strconv.Itoa(code) + " " + http.StatusText(code))...)

	return append(req, headersAndBody(headers, body)...)
}

func headersAndBody(headers map[string]string, body []string) []byte {
	req := make([]byte, 0, 1024)

	var seenCL bool
	for k, v := range headers {
		req = append(req, '\n')
		req = append(req, (k + ": " + v)...)
		if strings.ToLower(k) == "content-length" {
			seenCL = true
		}
	}

	if len(body) > 0 {
		if !seenCL {
			l := 0
			for _, b := range body {
				l += len(b)
			}
			req = append(req, '\n')
			req = append(req, "Content-Length: "+strconv.Itoa(l)...)
		}
		req = append(req, '\n', '\n')
		for _, b := range body {
			req = append(req, b...)
		}

	} else {
		req = append(req, '\n', '\n')
	}

	return req
}
