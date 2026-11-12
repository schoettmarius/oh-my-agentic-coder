package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ProxyPolicy decides which hosts the filtered-mode proxy forwards to.
// There is no interactive prompt (an omac feature deliberately not
// recreated): a host is reachable if and only if it is loopback or on the
// allow list and not on the deny list.
type ProxyPolicy struct {
	Allow []string
	Deny  []string
}

// AllowedHost reports whether hostPort (host or host:port) may be
// reached. Deny wins over allow; loopback is always admitted; allow
// entries match the host itself and its subdomains; an empty allow list
// means every non-loopback host is blocked.
func (p ProxyPolicy) AllowedHost(hostPort string) bool {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range p.Deny {
		if domainMatches(host, strings.ToLower(d)) {
			return false
		}
	}
	if isLoopbackHost(host) {
		return true
	}
	for _, d := range p.Allow {
		if domainMatches(host, strings.ToLower(d)) {
			return true
		}
	}
	return false
}

// domainMatches reports whether host equals domain or is a subdomain of
// it (entries with a trailing '*' are treated as suffix matches).
func domainMatches(host, domain string) bool {
	domain = strings.TrimPrefix(domain, "*.")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Proxy is the local HTTP proxy the sandboxed agent is pointed at with
// HTTP(S)_PROXY. HTTPS goes through CONNECT tunneling, plain HTTP through
// absolute-URI forwarding; DNS for the target happens on the host side,
// so the sandbox needs no UDP at all.
type Proxy struct {
	srv       *http.Server
	ln        net.Listener
	port      int
	transport *http.Transport
	policy    ProxyPolicy
}

func StartProxy(policy ProxyPolicy) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	p := &Proxy{
		ln:   ln,
		port: ln.Addr().(*net.TCPAddr).Port,
		transport: &http.Transport{
			// Zero-value Transport dials directly; the host's own proxy
			// environment must not influence where traffic goes.
			MaxIdleConns:          8,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		policy: policy,
	}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

func (p *Proxy) Port() int    { return p.port }
func (p *Proxy) Close() error { return p.srv.Close() }

// EnvVars points HTTP clients at the proxy. Loopback stays direct via
// NO_PROXY so the agent can still reach loopback services granted with
// --open-port without a pointless detour.
func (p *Proxy) EnvVars() map[string]string {
	u := fmt.Sprintf("http://127.0.0.1:%d", p.port)
	no := "localhost,127.0.0.1,::1"
	return map[string]string{
		"HTTP_PROXY": u, "http_proxy": u,
		"HTTPS_PROXY": u, "https_proxy": u,
		"NO_PROXY": no, "no_proxy": no,
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	if !p.policy.AllowedHost(r.Host) {
		denyResponse(w, r.Host)
		return
	}
	dst, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("minimal-omac proxy: dial %s: %v", r.Host, err), http.StatusBadGateway)
		return
	}
	defer dst.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "minimal-omac proxy: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("minimal-omac proxy: hijack: %v", err), http.StatusInternalServerError)
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dst, buf); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, dst); done <- struct{}{} }()
	<-done
	<-done
}

// serveForward handles plain-HTTP absolute-URI requests by round-tripping
// them host-side. HTTPS never arrives here; clients tunnel it via
// CONNECT.
func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "minimal-omac proxy: expected an absolute URI (is the client configured to use this proxy?)", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, fmt.Sprintf("minimal-omac proxy: unsupported scheme %q (HTTPS must go through CONNECT)", r.URL.Scheme), http.StatusBadRequest)
		return
	}
	if !p.policy.AllowedHost(r.URL.Host) {
		denyResponse(w, r.URL.Host)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, fmt.Sprintf("minimal-omac proxy: upstream %s: %v", r.URL.Host, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func denyResponse(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w,
		"minimal-omac proxy: %s is not in the network allow list.\n"+
			"Allow it by adding it to network.allow_domain in the profile\n"+
			"and restarting the sandbox.\n", host)
}
