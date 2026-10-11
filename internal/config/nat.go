package config

import (
	"fmt"
	"strings"
)

// NATForward is one port (or port range) the router in front of FreeSBC must
// forward to public.bind, with the same number on both sides.
type NATForward struct {
	Proto string // "udp" or "tcp"
	Ports string // "5060" or "20000-29999"
	Label string // the edge.listen key, "rtp" for media
}

// String renders "udp/5060", plus " (label)" when the label adds information.
func (f NATForward) String() string {
	s := f.Proto + "/" + f.Ports
	if f.Label != "" && f.Label != f.Proto {
		s += " (" + f.Label + ")"
	}
	return s
}

// NATMode reports whether FreeSBC sits behind 1:1 NAT: the advertised
// public.ip is not the address public sockets bind.
func (c *Config) NATMode() bool { return c.PublicBind() != c.PublicIP() }

// NATForwards lists every public port that must be reachable from clients:
// each configured edge.listen socket, then the rtp range over UDP. It is nil
// outside NAT mode. The admin API and the private socket are not here: neither
// binds on public.bind.
func (c *Config) NATForwards() []NATForward {
	if !c.NATMode() {
		return nil
	}
	var out []NATForward
	for _, l := range []struct {
		label string
		port  int
	}{{"udp", c.Edge.Listen.UDP}, {"tcp", c.Edge.Listen.TCP}, {"tls", c.Edge.Listen.TLS},
		{"ws", c.Edge.Listen.WS}, {"wss", c.Edge.Listen.WSS}} {
		if l.port == 0 {
			continue
		}
		proto := "tcp"
		if l.label == "udp" {
			proto = "udp"
		}
		out = append(out, NATForward{Proto: proto, Ports: fmt.Sprint(l.port), Label: l.label})
	}
	out = append(out, NATForward{Proto: "udp", Ports: fmt.Sprintf("%d-%d", c.RTP.Min, c.RTP.Max), Label: "rtp"})
	return out
}

// NATChecklist is the text `check`, `run` and `init` show for a 1:1 NAT
// setup: the advertised endpoints and the port forwards the router needs. It
// is empty outside NAT mode, and ends with a newline otherwise.
func (c *Config) NATChecklist() string {
	fw := c.NATForwards()
	if fw == nil {
		return ""
	}
	var adv, req []string
	for _, f := range fw {
		adv = append(adv, f.String())
		req = append(req, "  "+f.String())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "NAT mode: advertised public endpoint = %s (%s)\n", c.Public.IP, strings.Join(adv, " "))
	fmt.Fprintf(&b, "REQUIRED forwards -> %s (same port numbers):\n%s\n", c.Public.Bind, strings.Join(req, "\n"))
	b.WriteString("in-dialog requests (2xx ACK, BYE) use Contact/Record-Route, not Via:\n")
	b.WriteString("these ports MUST be reachable from clients.\n")
	return b.String()
}
