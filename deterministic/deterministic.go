package deterministic

import (
	"errors"
	"fmt"
	"sort"

	"github.com/ovh/symmecrypt"
)

type SaltConfig struct {
	Identifier string `json:"identifier,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	Value      string `json:"value"`
}

type KeyConfig struct {
	Identifier string       `json:"identifier,omitempty"`
	Cipher     string       `json:"cipher"`
	Salt       []SaltConfig `json:"salt,omitempty"`
	Timestamp  int64        `json:"timestamp,omitempty"`
}

func NewKey(key string, cfgs ...KeyConfig) (symmecrypt.Key, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("missing key config")
	}

	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Timestamp > cfgs[j].Timestamp })

	var comp symmecrypt.CompositeKey
	for i := range cfgs {
		cfg := &cfgs[i]
		// sort by timestamp: latest (bigger timestamp) first
		sort.Slice(cfg.Salt, func(i, j int) bool { return cfg.Salt[i].Timestamp > cfg.Salt[j].Timestamp })

		var ref symmecrypt.Key
		factory, err := symmecrypt.GetKeyFactory(cfg.Cipher)
		if err != nil {
			return nil, fmt.Errorf("unable to get key factory: %w", err)
		}

		if len(cfg.Salt) == 0 {
			ref, err = factory.NewSequentialKey(key)
			if err != nil {
				return nil, fmt.Errorf("unable to create new key: %w", err)
			}
			comp = append(comp, ref)
		} else {
			for j := range cfg.Salt {
				salt := &cfg.Salt[j]
				ref, err = factory.NewSequentialKey(key, []byte(salt.Value)...)
				if err != nil {
					return nil, fmt.Errorf("unable to create new key: %w", err)
				}
				comp = append(comp, ref)
			}
		}
	}

	// if only a single key config was provided, decapsulate the composite key
	if len(comp) == 1 {
		return comp[0], nil
	}

	return comp, nil
}
