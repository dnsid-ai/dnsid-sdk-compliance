package main

import dnsid "github.com/dnsid-ai/dnsid-go"

// newLocalIdentityManager builds a local-identity manager with the current
// dnsid-go Config API.
func newLocalIdentityManager(cfg txtRecordConfig, flags []dnsid.PolicyFlag, operational dnsid.KeyProvider, options []dnsid.IdentityManagerOption) (*dnsid.IdentityManager, error) {
	return dnsid.NewIdentityManager(dnsid.Config{Identity: &dnsid.IdentityConfig{
		Domain:          cfg.Domain,
		GovernanceID:    cfg.GovernanceID,
		LogRef:          cfg.LogRef,
		StatusURL:       cfg.StatusURL,
		EntityKeyURL:    cfg.EKURL,
		KeyURL:          cfg.KUURL,
		PublishProfile:  cfg.PublishProfile,
		PolicyFlags:     flags,
		MaxKeyAge:       dnsid.KeyAge(cfg.MaxKeyAge),
		CapabilitiesURL: cfg.CapabilitiesURL,
	}}, operational, options...)
}
