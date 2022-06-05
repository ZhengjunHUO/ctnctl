package models

type L3Entry string

type L4Entry struct {
	IP	string		`yaml:"ip" validate:"required"`
	Port	uint16		`yaml:"port" validate:"required"`
}

type FirewallConfig struct {
	PodName		string		`yaml:"podName" validate:"required"`
	IngressRules struct {
		L3	[]L3Entry	`yaml:"l3" validate:"omitempty"`
		L4	[]L4Entry	`yaml:"l4" validate:"omitempty"`
	}
	EgressRules struct {
		L3	[]L3Entry	`yaml:"l3" validate:"omitempty"`
		L4	[]L4Entry	`yaml:"l4" validate:"omitempty"`
	}
}
