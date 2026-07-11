package openconnect

import (
	"net/netip"
	"time"
)

type TunnelConfigurationEventReason string

const (
	TunnelConfigurationEventInitial         TunnelConfigurationEventReason = "initial"
	TunnelConfigurationEventReestablishment TunnelConfigurationEventReason = "reestablishment"
	TunnelConfigurationEventRekey           TunnelConfigurationEventReason = "rekey"
	TunnelConfigurationEventPathMTU         TunnelConfigurationEventReason = "path-mtu"
)

type TunnelConfiguration struct {
	MTU                      uint32
	Addresses                []netip.Prefix
	Routes                   []TunnelRoute
	ExcludedRoutes           []TunnelRoute
	DNS                      []netip.Addr
	NBNS                     []netip.Addr
	SearchDomains            []string
	SplitDNS                 []string
	SplitDNSRules            []TunnelSplitDNSRule
	ProxyAutoConfigURL       string
	Banner                   string
	TunnelAllDNS             bool
	ClientBypassProtocol     bool
	IdleTimeout              time.Duration
	AuthenticationExpiration time.Time
}

type TunnelSplitDNSRule struct {
	Domains []string
	Servers []netip.Addr
}

type TunnelRoute struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
	Metric  int
}

type TunnelConfigurationEvent struct {
	Reason        TunnelConfigurationEventReason
	Configuration TunnelConfiguration
}

func cloneTunnelConfiguration(configuration TunnelConfiguration) TunnelConfiguration {
	configuration.Addresses = append([]netip.Prefix(nil), configuration.Addresses...)
	configuration.Routes = append([]TunnelRoute(nil), configuration.Routes...)
	configuration.ExcludedRoutes = append([]TunnelRoute(nil), configuration.ExcludedRoutes...)
	configuration.DNS = append([]netip.Addr(nil), configuration.DNS...)
	configuration.NBNS = append([]netip.Addr(nil), configuration.NBNS...)
	configuration.SearchDomains = append([]string(nil), configuration.SearchDomains...)
	configuration.SplitDNS = append([]string(nil), configuration.SplitDNS...)
	configuration.SplitDNSRules = append([]TunnelSplitDNSRule(nil), configuration.SplitDNSRules...)
	for ruleIndex := range configuration.SplitDNSRules {
		configuration.SplitDNSRules[ruleIndex].Domains = append([]string(nil), configuration.SplitDNSRules[ruleIndex].Domains...)
		configuration.SplitDNSRules[ruleIndex].Servers = append([]netip.Addr(nil), configuration.SplitDNSRules[ruleIndex].Servers...)
	}
	return configuration
}
