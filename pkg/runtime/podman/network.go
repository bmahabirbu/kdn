// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package podman

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	workspace "github.com/openkaiden/kdn-api/workspace-configuration/go"
	"github.com/openkaiden/kdn/pkg/config"
	"github.com/openkaiden/kdn/pkg/onecli"
	"github.com/openkaiden/kdn/pkg/secret"
	"github.com/openkaiden/kdn/pkg/secretservice"
)

// loadNetworkConfig reads the merged workspace configuration for a project by
// combining workspace-level, project-level, and agent-level configs. It mirrors
// the merge logic used at workspace creation time so that edits take effect on
// the next Start() without recreating the workspace.
// Precedence (highest to lowest): agent > project > workspace.
func loadNetworkConfig(sourcePath, storageDir, projectID, agentName string) (*workspace.WorkspaceConfiguration, error) {
	merger := config.NewMerger()

	var merged *workspace.WorkspaceConfiguration

	wsCfgLoader, err := config.NewConfig(filepath.Join(sourcePath, ".kaiden"))
	if err != nil {
		return nil, fmt.Errorf("initializing workspace config loader: %w", err)
	}
	if wc, loadErr := wsCfgLoader.Load(); loadErr == nil {
		merged = wc
	}

	projectLoader, err := config.NewProjectConfigLoader(storageDir)
	if err != nil {
		return nil, fmt.Errorf("initializing project config loader: %w", err)
	}
	if pc, loadErr := projectLoader.Load(projectID); loadErr == nil {
		merged = merger.Merge(merged, pc)
	}

	if agentName != "" {
		agentLoader, err := config.NewAgentConfigLoader(storageDir)
		if err != nil {
			return nil, fmt.Errorf("initializing agent config loader: %w", err)
		}
		if ac, loadErr := agentLoader.Load(agentName); loadErr == nil {
			merged = merger.Merge(merged, ac)
		}
	}

	return merged, nil
}

// collectSecretHosts returns the host patterns contributed by the secrets
// listed in wsCfg. For known secret types, patterns come from the secret
// service registry; for "other" secrets, they come from the stored metadata.
// Returns nil when any required input is nil or when no secrets are configured.
func collectSecretHosts(wsCfg *workspace.WorkspaceConfiguration, store secret.Store, registry secretservice.Registry) ([]string, error) {
	if wsCfg == nil || wsCfg.Secrets == nil || len(*wsCfg.Secrets) == 0 {
		return nil, nil
	}
	if store == nil || registry == nil {
		return nil, nil
	}

	items, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	byName := make(map[string]secret.ListItem, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}

	seen := make(map[string]bool)
	var hosts []string
	for _, name := range *wsCfg.Secrets {
		item, ok := byName[name]
		if !ok {
			continue
		}
		var itemHosts []string
		if item.Type == secret.TypeOther {
			itemHosts = item.Hosts
		} else {
			svc, svcErr := registry.Get(item.Type)
			if svcErr != nil {
				continue
			}
			itemHosts = svc.HostsPatterns()
		}
		for _, h := range itemHosts {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return hosts, nil
}

// mergeHosts returns a deduplicated list of all hosts from a and b,
// preserving order (a first, then new entries from b).
func mergeHosts(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, h := range a {
		if !seen[h] {
			seen[h] = true
			result = append(result, h)
		}
	}
	for _, h := range b {
		if !seen[h] {
			seen[h] = true
			result = append(result, h)
		}
	}
	return result
}

// approvalHandlerConfig is serialized to config.json in the approval-handler
// directory so the Node.js sidecar can connect to OneCLI and make decisions.
type approvalHandlerConfig struct {
	OnecliURL  string   `json:"onecliUrl"`
	GatewayURL string   `json:"gatewayUrl"`
	APIKey     string   `json:"apiKey"`
	Hosts      []string `json:"hosts"`
}

// clearNetworkingRules removes all existing networking rules from OneCLI.
// Called when switching to allow mode so that no leftover manual_approval or
// block rules from a previous deny-mode start remain active.
func (p *podmanRuntime) clearNetworkingRules(ctx context.Context, onecliBaseURL string) error {
	creds := onecli.NewCredentialProvider(onecliBaseURL)
	apiKey, err := creds.APIKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OneCLI API key: %w", err)
	}

	client := onecli.NewClient(onecliBaseURL, apiKey)

	rules, err := client.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("listing existing rules: %w", err)
	}
	for _, r := range rules {
		if delErr := client.DeleteRule(ctx, r.ID); delErr != nil {
			return fmt.Errorf("deleting rule %s: %w", r.ID, delErr)
		}
	}
	return nil
}

// configureNetworking applies deny-mode networking via the OneCLI manual
// approval mechanism. It deletes any existing rules, creates a single
// manual_approval rule for all hosts, and writes config.json so the
// approval-handler sidecar knows which hosts to approve.
func (p *podmanRuntime) configureNetworking(ctx context.Context, onecliBaseURL string, hosts []string, approvalHandlerDir string) error {
	creds := onecli.NewCredentialProvider(onecliBaseURL)
	apiKey, err := creds.APIKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OneCLI API key: %w", err)
	}

	client := onecli.NewClient(onecliBaseURL, apiKey)

	rules, err := client.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("listing existing rules: %w", err)
	}
	for _, r := range rules {
		if delErr := client.DeleteRule(ctx, r.ID); delErr != nil {
			return fmt.Errorf("deleting rule %s: %w", r.ID, delErr)
		}
	}

	if _, err := client.CreateRule(ctx, onecli.CreateRuleInput{
		Name:        "manual-approval-all",
		HostPattern: "*",
		Action:      "manual_approval",
		Enabled:     true,
	}); err != nil {
		return fmt.Errorf("creating manual_approval rule: %w", err)
	}

	// The sidecar runs inside the pod and shares the network namespace with
	// OneCLI, so it must use the internal container ports, not the host-mapped
	// ports that the Go CLI uses from outside the pod.
	// API (10254) is used for rule management; gateway (10255) is used for
	// manual approval long-polling.
	cfg := approvalHandlerConfig{
		OnecliURL:  "http://localhost:10254",
		GatewayURL: "http://localhost:10255",
		APIKey:     apiKey,
		Hosts:      hosts,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling approval handler config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(approvalHandlerDir, "config.json"), data, 0644); err != nil {
		return fmt.Errorf("writing approval handler config: %w", err)
	}

	return nil
}


// setupAgentFirewall applies nftables rules inside the agent container to
// restrict outbound connections to only the OneCLI gateway proxy port.
// This prevents the agent from accessing OneCLI's API (10254), postgres
// (5432), or any other service on the internal network.
//
// Rules:
//   - ALLOW loopback (localhost)
//   - ALLOW OneCLI gateway IP on port 10255 (proxy)
//   - DENY everything else
func (p *podmanRuntime) setupAgentFirewall(ctx context.Context, containerID, gatewayIP string) error {
	script := buildAgentFirewallScript(gatewayIP)
	if err := p.executor.Run(ctx, io.Discard, io.Discard,
		"exec", "--user", "root", containerID, "sh", "-c", script,
	); err != nil {
		return fmt.Errorf("failed to set up agent firewall rules: %w", err)
	}
	return nil
}

// resolveGatewayIP discovers the OneCLI pod's IP address on the internal
// network by inspecting the infra container.
func (p *podmanRuntime) resolveGatewayIP(ctx context.Context, podName, networkName string) (string, error) {
	infraID, err := p.findPodInfraContainer(ctx, podName)
	if err != nil {
		return "", err
	}
	format := fmt.Sprintf(`{{(index .NetworkSettings.Networks "%s").IPAddress}}`, networkName)
	out, err := p.executor.Output(ctx, io.Discard, "inspect", infraID, "--format", format)
	if err != nil {
		return "", fmt.Errorf("failed to inspect infra container network: %w", err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("infra container has no IP on network %s", networkName)
	}
	return ip, nil
}

// buildAgentFirewallScript generates nftables commands that restrict the agent
// container's outbound to only the OneCLI gateway proxy port (10255).
func buildAgentFirewallScript(gatewayIP string) string {
	// Derive the DNS server IP from the gateway IP — podman's internal DNS
	// runs on the .1 address of the subnet (e.g., 10.89.1.1 for 10.89.1.x).
	dnsIP := gatewayIP[:strings.LastIndex(gatewayIP, ".")] + ".1"

	parts := []string{
		"command -v nft >/dev/null 2>&1 || dnf install -y nftables >/dev/null 2>&1",
		"nft delete table inet agent-firewall 2>/dev/null || true",
		"nft add table inet agent-firewall",
		"nft add chain inet agent-firewall output '{ type filter hook output priority 0; policy drop; }'",
		"nft add rule inet agent-firewall output oif lo accept",
		"nft add rule inet agent-firewall output ct state established,related accept",
		fmt.Sprintf("nft add rule inet agent-firewall output ip daddr %s udp dport 53 accept", dnsIP),
		fmt.Sprintf("nft add rule inet agent-firewall output ip daddr %s tcp dport 10255 accept", gatewayIP),
	}
	return strings.Join(parts, " && ")
}

// isPodmanWSL reports whether the podman machine uses the WSL2 provider.
func (p *podmanRuntime) isPodmanWSL(ctx context.Context) bool {
	out, err := p.executor.Output(ctx, io.Discard,
		"machine", "info", "--format", "{{.Host.VMType}}",
	)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "wsl"
}

// parseIPv4 validates and normalizes a string as an IPv4 address.
// Returns the canonical form or empty string if invalid, multiline, or IPv6.
func parseIPv4(s string) string {
	if strings.ContainsAny(s, "\n\r") {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if ip.To4() == nil {
		return ""
	}
	return ip.String()
}

// resolveWSLHostIP returns the default gateway IP from inside the podman
// machine via SSH. On WSL2 this is the Windows host IP.
func (p *podmanRuntime) resolveWSLHostIP(ctx context.Context) string {
	out, err := p.executor.Output(ctx, io.Discard,
		"machine", "ssh", "ip", "route", "show", "default",
	)
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) >= 3 {
		return parseIPv4(fields[2])
	}
	return ""
}

// injectWSLHostEntry adds or updates a host.containers.internal entry in
// /etc/hosts inside the workspace container, mapping it to the Windows
// host IP read from the podman machine's /etc/resolv.conf via SSH.
// Filters out any existing entry before appending so repeated Start()
// calls don't accumulate stale lines.
func (p *podmanRuntime) injectWSLHostEntry(ctx context.Context, containerID string) error {
	hostIP := p.resolveWSLHostIP(ctx)
	if hostIP == "" {
		return fmt.Errorf("failed to resolve Windows host IP from podman machine")
	}

	// /etc/hosts is a mount in containers — sed -i fails because it tries to
	// rename a temp file over the mount. Use grep + tee to modify in-place.
	cmd := fmt.Sprintf(
		"grep -v 'host\\.containers\\.internal' /etc/hosts > /tmp/hosts.tmp && cp /tmp/hosts.tmp /etc/hosts && rm /tmp/hosts.tmp && echo '%s host.containers.internal' >> /etc/hosts",
		hostIP,
	)
	if err := p.executor.Run(ctx, io.Discard, io.Discard,
		"exec", "--user", "root", containerID, "sh", "-c", cmd,
	); err != nil {
		return fmt.Errorf("failed to update /etc/hosts entry: %w", err)
	}
	return nil
}

