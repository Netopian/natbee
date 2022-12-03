package config

import (
	"natbee/internal/comm"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type ConfigSet struct {
	Global   Global     `mapstructure:"global" yaml:"global"`
	Nat      Balancer   `mapstructure:"nat" yaml:"nat"`
	FNat     Balancer   `mapstructure:"fnat" yaml:"fnat"`
	wrLock   sync.Mutex `mapstructure:"-" yaml:"-"`
	filePath string     `mapstructure:"-" yaml:"-"`
}

func ReadConfigfile(path string) (*ConfigSet, error) {
	filePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	config := &ConfigSet{filePath: filePath}
	v := viper.New()
	v.SetConfigFile(filePath)
	v.SetConfigType("yaml")
	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err = v.UnmarshalExact(config); err != nil {
		return nil, err
	}
	config.setDefaultValue()
	return config, nil
}

func (c *ConfigSet) AttachNat(ip string) {
	c.wrLock.Lock()
	c.Nat.Attach(ip)
	c.wrLock.Unlock()
}

func (c *ConfigSet) DetachNat(ip string) {
	c.wrLock.Lock()
	c.Nat.Detach(ip)
	c.wrLock.Unlock()
}

func (c *ConfigSet) AddNat(s Service) {
	c.wrLock.Lock()
	c.Nat.Add(s)
	c.wrLock.Unlock()
}

func (c *ConfigSet) DelNat(s Service) {
	c.wrLock.Lock()
	c.Nat.Del(s)
	c.wrLock.Unlock()
}

func (c *ConfigSet) AttachFNat(ip string) {
	c.wrLock.Lock()
	c.FNat.Attach(ip)
	c.wrLock.Unlock()
}

func (c *ConfigSet) DetachFNat(ip string) {
	c.wrLock.Lock()
	c.FNat.Detach(ip)
	c.wrLock.Unlock()
}

func (c *ConfigSet) AddFNat(s Service) {
	c.wrLock.Lock()
	c.FNat.Add(s)
	c.wrLock.Unlock()
}

func (c *ConfigSet) DelFNat(s Service) {
	c.wrLock.Lock()
	c.FNat.Del(s)
	c.wrLock.Unlock()
}

func (c *ConfigSet) Save(path string) error {
	var (
		filePath string
		err      error
	)
	if len(path) > 0 {
		filePath, err = filepath.Abs(path)
		if err != nil {
			return err
		}
	}
	c.wrLock.Lock()
	defer c.wrLock.Unlock()
	v := viper.New()
	v.SetConfigType("yaml")
	v.Set("global", c.Global)
	v.Set("nat", c.Nat)
	v.Set("fnat", c.FNat)
	if len(filePath) > 0 {
		err = v.WriteConfigAs(filePath)
	} else {
		err = v.WriteConfigAs(c.filePath)
	}
	if err != nil {
		log.Errorf("save configuration failed: %v", err)
		return err
	}
	return nil
}

func (c *ConfigSet) setDefaultValue() {
	if c.Global.ConnTimeout == 0 {
		c.Global.ConnTimeout = comm.DefaultConnTimeout
	}
}
