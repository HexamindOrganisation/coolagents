package hexgatebiscuitauth

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

// typeStr is the name this authenticator is referenced by in config.yaml.
var typeStr = component.MustNewType("hexgatebiscuitauth")

// NewFactory returns the factory ocb wires into components.go.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		typeStr,
		createDefaultConfig,
		createExtension,
		// Development: this has never run against real traffic. Raise once
		// it has been exercised end-to-end in staging (design doc PR #6).
		component.StabilityLevelDevelopment,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Revocation: RevocationConfig{
			// On by default. Opting out is a real decision an operator has to
			// write down, because API keys are minted without a TTL, so
			// signature checks alone would honour a leaked key forever.
			Enabled:      true,
			PollInterval: defaultPollInterval,
			MaxStaleness: defaultMaxStaleness,
		},
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return &biscuitAuth{
		cfg:    cfg.(*Config),
		logger: set.Logger,
	}, nil
}
