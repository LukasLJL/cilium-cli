// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// PodToService sends an HTTP request from all client Pods
// to all Services in the test context.
func PodToService(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToService{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToService implements a Scenario.
type podToService struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToService) Name() string {
	return "pod-to-service"
}

func (s *podToService) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.EchoServices() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				backends, err := svc.BackendEndpoints(ctx, ct.K8sClient(), ipFamily)
				if err != nil {
					t.Fatalf("Failed to resolve backends for service %s: %v", svc.Name(), err)
					return
				}
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))

					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						AltDstEndpoints: backends,
					}))

					a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
				})
			})
			i++
		}
	}
}

// PodToIngress sends an HTTP request from all client Pods
// to all Ingress service in the test context.
func PodToIngress(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToIngress{
		ScenarioBase:      check.NewScenarioBase(),
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToIngress implements a Scenario.
type podToIngress struct {
	check.ScenarioBase

	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToIngress) Name() string {
	return "pod-to-ingress-service"
}

func (s *podToIngress) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.IngressService() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			if versioncheck.MustCompile(">=1.17.0")(ct.CiliumVersion) {
				t.ForEachIPFamily(func(ipFam features.IPFamily) {
					t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &pod, svc, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, a.CurlCommand(svc))

						a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
							DNSRequired: true,
							AltDstPort:  svc.Port(),
						}))
					})
				})
			} else {
				t.NewAction(s, fmt.Sprintf("curl-%d", i), &pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))

					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))
				})
			}

			i++
		}
	}
}

// PodToRemoteNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only to other nodes.
func PodToRemoteNodePort() check.Scenario {
	return &podToRemoteNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToRemoteNodePort implements a Scenario.
type podToRemoteNodePort struct {
	check.ScenarioBase
}

func (s *podToRemoteNodePort) Name() string {
	return "pod-to-remote-nodeport"
}

func (s *podToRemoteNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().Nodes() {
				remote := true
				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						remote = false
						break
					}
				}
				if !remote {
					continue
				}

				// If src and dst pod are running on different nodes,
				// call the Cilium Pod's host IP on the service's NodePort.
				curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

				i++
			}
		}
	}
}

// PodToLocalNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only on the same node as
// the client Pods.
func PodToLocalNodePort() check.Scenario {
	return &podToLocalNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToLocalNodePort implements a Scenario.
type podToLocalNodePort struct {
	check.ScenarioBase
}

func (s *podToLocalNodePort) Name() string {
	return "pod-to-local-nodeport"
}

func (s *podToLocalNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().Nodes() {
				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						// If src and dst pod are running on the same node,
						// call the Cilium Pod's host IP on the service's NodePort.
						curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

						i++
					}
				}
			}
		}
	}
}

func curlNodePort(ctx context.Context, s check.Scenario, t *check.Test,
	name string, pod *check.Pod, svc check.Service, node *slimcorev1.Node,
	validateFlows bool, secondaryNetwork bool) {

	// Get the NodePort allocated to the Service.
	np := uint32(svc.Service.Spec.Ports[0].NodePort)

	addrs := slices.Clone(node.Status.Addresses)

	if secondaryNetwork {
		if t.Context().Features[features.IPv4].Enabled {
			addrs = append(addrs, slimcorev1.NodeAddress{
				Type:    "SecondaryNetworkIPv4",
				Address: t.Context().SecondaryNetworkNodeIPv4()[node.Name],
			})
		}
		if t.Context().Features[features.IPv6].Enabled {
			addrs = append(addrs, slimcorev1.NodeAddress{
				Type:    "SecondaryNetworkIPv6",
				Address: t.Context().SecondaryNetworkNodeIPv6()[node.Name],
			})
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {

		for _, addr := range addrs {
			if features.GetIPFamily(addr.Address) != ipFam {
				continue
			}

			// On GKE ExternalIP is not reachable from inside a cluster
			if addr.Type == slimcorev1.NodeExternalIP {
				if f, ok := t.Context().Feature(features.Flavor); ok && f.Enabled && f.Mode == "gke" {
					continue
				}
			}

			// Manually construct an HTTP endpoint to override the destination IP
			// and port of the request.
			ep := check.HTTPEndpoint(name, fmt.Sprintf("%s://%s%s", svc.Scheme(), net.JoinHostPort(addr.Address, strconv.FormatUint(uint64(np), 10)), svc.Path()))

			// Create the Action with the original svc as this will influence what the
			// flow matcher looks for in the flow logs.
			t.NewAction(s, name, pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommand(ep))

				if validateFlows {
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						// The fact that curl is hitting the NodePort instead of the
						// backend Pod's port is specified here. This will cause the matcher
						// to accept both the NodePort and the ClusterIP (container) port.
						AltDstPort: np,
					}))
				}
			})
		}
	})
}

// OutsideToNodePort sends an HTTP request from client pod running on a node w/o
// Cilium to NodePort services.
func OutsideToNodePort() check.Scenario {
	return &outsideToNodePort{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type outsideToNodePort struct {
	check.ScenarioBase
}

func (s *outsideToNodePort) Name() string {
	return "outside-to-nodeport"
}

func (s *outsideToNodePort) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	// With kube-proxy doing N/S LB it is not possible to see the original client
	// IP, as iptables rules do the LB SNAT/DNAT before the packet hits any
	// of Cilium's datapath BPF progs. So, skip the flow validation in that case.
	status, ok := t.Context().Feature(features.KPR)
	validateFlows := ok && status.Enabled

	for _, svc := range t.Context().EchoServices() {
		for _, node := range t.Context().Nodes() {
			curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &clientPod, svc, node, validateFlows, t.Context().Params().SecondaryNetworkIface != "")
			i++
		}
	}
}

// OutsideToIngressService sends an HTTP request from client pod running on a node w/o
// Cilium to NodePort services.
func OutsideToIngressService() check.Scenario {
	return &outsideToIngressService{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type outsideToIngressService struct {
	check.ScenarioBase
}

func (s *outsideToIngressService) Name() string {
	return "outside-to-ingress-service"
}

func (s *outsideToIngressService) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	for _, svc := range t.Context().IngressService() {
		t.NewAction(s, fmt.Sprintf("curl-ingress-service-%d", i), &clientPod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
			for _, node := range t.Context().Nodes() {
				a.ExecInPod(ctx, a.CurlCommand(svc.ToNodeportService(node)))

				a.ValidateFlows(ctx, clientPod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: true,
					AltDstPort:  svc.Port(),
				}))
			}
		})
		i++
	}
}

// PodToL7Service sends an HTTP request from a given client Pods
// to all L7 LB service in the test context.
func PodToL7Service(name string, clients map[string]check.Pod, opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToL7Service{
		ScenarioBase:      check.NewScenarioBase(),
		name:              name,
		clients:           clients,
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToL7Service implements a Scenario.
type podToL7Service struct {
	check.ScenarioBase

	name              string
	clients           map[string]check.Pod
	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToL7Service) Name() string {
	if len(s.name) == 0 {
		return "pod-to-l7-lb-service"
	}
	return fmt.Sprintf("pod-to-l7-lb-service-%s", s.name)
}

func (s *podToL7Service) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range s.clients {
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}

		for _, svc := range ct.L7LBService() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}
			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				backends, err := svc.BackendEndpoints(ctx, ct.K8sClient(), ipFamily)
				if err != nil {
					t.Fatalf("Failed to resolve backends for service %s: %v", svc.Name(), err)
					return
				}
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						AltDstEndpoints: backends,
					}))
				})
			})
			i++
		}
	}
}

// PodToItselfViaService sends an HTTP request from the client pod
// to the ClusterIP services of that pod in the test context
// to confirm hairpinning works.
func PodToItselfViaService() check.Scenario {
	return &podToItselfViaService{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToItselfViaService struct {
	check.ScenarioBase
}

const (
	defaultServiceLoopbackIPv4 = "169.254.42.1"
	defaultServiceLoopbackIPv6 = "fe80::1"
	serviceLoopbackIPv4Key     = "ipv4-service-loopback-address"
	serviceLoopbackIPv6Key     = "ipv6-service-loopback-address"
)

func (s *podToItselfViaService) Name() string {
	return "pod-to-itself-via-service"
}

func serviceLoopbackAddress(ctx context.Context, ct *check.ConnectivityTest, family features.IPFamily) (string, error) {
	configMap, err := ct.K8sClient().GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("retrieving ConfigMap %s/%s for service loopback address: %w", ct.Params().CiliumNamespace, defaults.ConfigMapName, err)
	}
	return configuredServiceLoopbackAddress(configMap.Data, family)
}

func configuredServiceLoopbackAddress(config map[string]string, family features.IPFamily) (string, error) {
	key, address := serviceLoopbackIPv4Key, defaultServiceLoopbackIPv4
	if family == features.IPFamilyV6 {
		key, address = serviceLoopbackIPv6Key, defaultServiceLoopbackIPv6
	}
	if configured := config[key]; configured != "" {
		address = configured
	}

	ip := net.ParseIP(address)
	if ip == nil || (family == features.IPFamilyV4) != (ip.To4() != nil) {
		return "", fmt.Errorf("invalid Cilium %s value %q", key, address)
	}
	return address, nil
}

func selfBackendEndpoints(pod check.Pod, backends []check.FlowEndpoint, family features.IPFamily) []check.FlowEndpoint {
	podIP := net.ParseIP(pod.Address(family))
	selfBackends := make([]check.FlowEndpoint, 0, 1)
	for _, backend := range backends {
		if podIP.Equal(net.ParseIP(backend.IP)) {
			selfBackends = append(selfBackends, backend)
		}
	}
	return selfBackends
}

type backendEndpointResolver func(context.Context, *k8s.Client, features.IPFamily) ([]check.FlowEndpoint, error)

func resolveSelfBackendEndpoints(ctx context.Context, client *k8s.Client, pod check.Pod, family features.IPFamily, resolve backendEndpointResolver) ([]check.FlowEndpoint, error) {
	backends, err := resolve(ctx, client, family)
	if err != nil {
		return nil, err
	}
	selfBackends := selfBackendEndpoints(pod, backends, family)
	if len(selfBackends) == 0 {
		return nil, fmt.Errorf("pod %s with %s address %s is not a ready service backend", pod.Name(), family, pod.Address(family))
	}
	return selfBackends, nil
}

func (s *podToItselfViaService) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.L7LBClientPods() {
		for _, svc := range ct.L7LBNonL7Service() {
			t.ForEachIPFamily(func(ipFamily features.IPFamily) {
				// Skip IPv6 for versions < 1.19.0
				if ipFamily == features.IPFamilyV6 && !versioncheck.MustCompile(">=1.19.0")(ct.CiliumVersion) {
					return
				}
				selfBackends, err := resolveSelfBackendEndpoints(ctx, ct.K8sClient(), pod, ipFamily, svc.BackendEndpoints)
				if err != nil {
					t.Fatalf("Failed to resolve self backend for service %s: %v", svc.Name(), err)
					return
				}
				loopbackIP, err := serviceLoopbackAddress(ctx, ct, ipFamily)
				if err != nil {
					t.Fatalf("Failed to resolve service loopback address: %v", err)
					return
				}

				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFamily, i), &pod, svc, ipFamily).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						AltDstEndpoints:           selfBackends,
						AltRequestSourceIPs:       []string{loopbackIP},
						AltResponseDestinationIPs: []string{loopbackIP},
					}))
					a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
				})
			})
			i++
		}
	}

}
