package config

type Global struct {
	NatFilePath  string `mapstructure:"nat-filepath" yaml:"nat-filepath"`
	FNatFilePath string `mapstructure:"fnat-filepath" yaml:"fnat-filepath"`
	ConnTimeout  uint32 `mapstructure:"conn-timeout" yaml:"conn-timeout"`
	Group        string `mapstructure:"group" yaml:"group"`
}

func (l *Global) Equal(r *Global) bool {
	if l == nil || r == nil {
		return false
	}
	if l.NatFilePath != r.NatFilePath {
		return false
	}
	if l.FNatFilePath != r.FNatFilePath {
		return false
	}
	if l.ConnTimeout != r.ConnTimeout {
		return false
	}
	if l.Group != r.Group {
		return false
	}
	return true
}

type Balancer struct {
	Attached             []string  `mapstructure:"attached" yaml:"attached"`
	Services             []Service `mapstructure:"services" yaml:"services"`
	UseTc                bool      `mapstructure:"use-tc" yaml:"use-tc,omitempty"`
	ExclusivePortEnabled bool      `mapstructure:"exclusive-port-enabled" yaml:"exclusive-port-enabled,omitempty"`
}

func (l *Balancer) Equal(r *Balancer) bool {
	if l == nil || r == nil {
		return false
	}
	if len(l.Attached) != len(r.Attached) {
		return false
	}
	for i, v := range l.Attached {
		if v != r.Attached[i] {
			return false
		}
	}
	if len(l.Services) != len(r.Services) {
		return false
	}
	for i, v := range l.Services {
		if !v.Equal(&r.Services[i]) {
			return false
		}
	}
	if l.UseTc != r.UseTc {
		return false
	}
	if l.ExclusivePortEnabled != r.ExclusivePortEnabled {
		return false
	}
	return true
}

func (c *Balancer) Attach(ip string) {
	c.Attached = append(c.Attached, ip)
}

func (c *Balancer) Detach(ip string) {
	for i, v := range c.Attached {
		if v == ip {
			c.Attached[i] = c.Attached[len(c.Attached)-1]
			c.Attached = c.Attached[:len(c.Attached)-1]
			break
		}
	}
}

func (c *Balancer) Add(s Service) {
	c.Services = append(c.Services, s)
}

func (c *Balancer) Del(s Service) {
	for i, v := range c.Services {
		if v.VirtualIP == s.VirtualIP && v.VirtualPort == s.VirtualPort && v.Protocol == s.Protocol {
			c.Services[i] = c.Services[len(c.Services)-1]
			c.Services = c.Services[:len(c.Services)-1]
			break
		}
	}
}

type Service struct {
	VirtualIP     string   `mapstructure:"virtual-ip" yaml:"virtual-ip,omitempty"`
	VirtualPort   uint32   `mapstructure:"virtual-port" yaml:"virtual-port,omitempty"`
	Protocol      string   `mapstructure:"protocol" yaml:"protocol,omitempty"`
	LocalIP       string   `mapstructure:"local-ip" yaml:"local-ip,omitempty"`
	RealPort      uint32   `mapstructure:"real-port" yaml:"real-port,omitempty"`
	ConnTimeout   uint32   `mapstructure:"conn-timeout" yaml:"conn-timeout,omitempty"`
	RealServerIPs []string `mapstructure:"real-server-ips" yaml:"real-server-ips,omitempty"`
}

func (l *Service) Equal(r *Service) bool {
	if l == nil || r == nil {
		return false
	}
	if l.VirtualIP != r.VirtualIP {
		return false
	}
	if l.VirtualPort != r.VirtualPort {
		return false
	}
	if l.Protocol != r.Protocol {
		return false
	}
	if l.LocalIP != r.LocalIP {
		return false
	}
	if l.RealPort != r.RealPort {
		return false
	}
	if l.ConnTimeout != r.ConnTimeout {
		return false
	}
	if len(l.RealServerIPs) != len(r.RealServerIPs) {
		return false
	}
	for i, v := range l.RealServerIPs {
		if v != r.RealServerIPs[i] {
			return false
		}
	}
	return true
}
