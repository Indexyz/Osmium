package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// LoginOptions configures Login.
type LoginOptions struct {
	Server string
	CAFile string
	// Open is called with the URL the user must visit (e.g. open a browser).
	Open    func(url string) error
	Timeout time.Duration
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const callbackPage = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>osmium</title>
<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto">%s</body></html>`

// Login runs the browser + loopback + PKCE flow and saves credentials.
func Login(ctx context.Context, o LoginOptions) (*Credentials, error) {
	srv, err := CheckServerURL(o.Server)
	if err != nil {
		return nil, err
	}
	hc, err := HTTPClient(o.CAFile)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	state, verifier := randomString(24), oauth2.GenerateVerifier()

	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 || q.Get("code") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, callbackPage, "无效的回调，请重新运行 osmium login。")
			return
		}
		fmt.Fprintf(w, callbackPage, "登录成功，可以关闭此页面回到终端。")
		select {
		case got <- result{code: q.Get("code")}:
		default:
		}
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()

	q := url.Values{"port": {strconv.Itoa(port)}, "state": {state}, "code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}}
	authURL := srv.String() + "/auth/cli?" + q.Encode()
	if o.Open != nil {
		if err := o.Open(authURL); err != nil {
			return nil, err
		}
	}
	var res result
	select {
	case res = <-got:
	case <-ctx.Done():
		return nil, errors.New("timed out waiting for browser authorization")
	}
	if res.err != nil {
		return nil, res.err
	}

	b, _ := json.Marshal(map[string]string{"code": res.code, "code_verifier": verifier})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.String()+"/auth/cli/token", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %d", resp.StatusCode)
	}
	var c Credentials
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&c); err != nil || c.Token == "" {
		return nil, errors.New("invalid token response")
	}
	c.Server, c.CAFile = srv.String(), o.CAFile
	if err := c.Save(); err != nil {
		return nil, err
	}
	return &c, nil
}
