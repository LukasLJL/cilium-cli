// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

var (
	//go:embed manifests/local-redirect-policy.yaml
	localRedirectPolicyYAML string
	//go:embed manifests/client-egress-to-cidr-lrp-frontend-deny.yaml
	localRedirectPolicyFrontendDenyYAML string
)

type localRedirectPolicy struct{}

const (
	lrpFrontendIPV4             = "169.254.169.249"
	lrpFrontendIPV6             = "fd00::169:254:169:249"
	lrpFrontendIPSkipRedirectV4 = "169.254.169.248"
	lrpFrontendIPSkipRedirectV6 = "fd00::169:254:169:248"
)

func (t localRedirectPolicy) build(ct *check.ConnectivityTest, _ map[string]string) {
	lrpTest := newTest("local-redirect-policy", ct).
		WithCondition(func() bool {
			return ct.IsSocketLBFull() || versioncheck.MustCompile(">=1.17.0")(ct.CiliumVersion)
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-v4",
			FrontendIP:              lrpFrontendIPV4,
			SkipRedirectFromBackend: false,
		}).
		WithCiliumPolicy(localRedirectPolicyFrontendDenyYAML).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-skip-redirect-from-backend-v4",
			FrontendIP:              lrpFrontendIPSkipRedirectV4,
			SkipRedirectFromBackend: true,
		})

	// Skip to apply CLRPs with ipv6 frontend if IPv6 is disabled to avoid the agent crash
	// caused by https://github.com/cilium/cilium/issues/38570
	if f, ok := ct.Features[features.IPv6]; ok && f.Enabled {
		lrpTest.WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-v6",
			FrontendIP:              lrpFrontendIPV6,
			SkipRedirectFromBackend: false,
		}).WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-skip-redirect-from-backend-v6",
			FrontendIP:              lrpFrontendIPSkipRedirectV6,
			SkipRedirectFromBackend: true,
		})
	}

	lrpTest.WithFeatureRequirements(features.RequireEnabled(features.LocalRedirectPolicy)).
		WithScenarios(
			tests.LRP(false),
			tests.LRP(true),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return localRedirectPolicyExpectedResult(
				a.Scenario().Name(),
				a.Source().HasLabel("lrp", "backend"),
				a.Destination().Address(features.IPFamilyV4),
				a.Destination().Address(features.IPFamilyV6),
			)
		})
}

func localRedirectPolicyExpectedResult(scenario string, sourceIsBackend bool, destinationV4, destinationV6 string) (check.Result, check.Result) {
	if scenario == "lrp-skip-redirect-from-backend" && sourceIsBackend &&
		(destinationV4 == lrpFrontendIPSkipRedirectV4 || destinationV6 == lrpFrontendIPSkipRedirectV6) {
		return check.ResultPolicyDenyEgressDrop, check.ResultNone
	}
	return check.ResultOK, check.ResultNone
}
