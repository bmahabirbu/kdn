/**********************************************************************
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package agent

import (
	"encoding/json"
	"fmt"

	workspace "github.com/openkaiden/kdn-api/workspace-configuration/go"
	kdnconfig "github.com/openkaiden/kdn/pkg/config"
)

const (
	// ClawConfigPath is the relative path to the OpenClaw configuration file.
	ClawConfigPath = ".openclaw/openclaw.json"

	// ClawTelegramScriptPath is the path where the Telegram startup script is placed.
	ClawTelegramScriptPath = "telegram-start.sh"

	// clawTelegramScript is the startup script for headless Telegram mode.
	clawTelegramScript = `#!/bin/bash
set -euo pipefail

openclaw channels add --channel telegram --token "$TELEGRAM_BOT_TOKEN" 2>/dev/null

openclaw gateway run --allow-unconfigured --auth none --bind loopback &
GATEWAY_PID=$!
sleep 3

echo "Gateway running (PID $GATEWAY_PID). Auto-approving pairings..."

while kill -0 "$GATEWAY_PID" 2>/dev/null; do
  CODES=$(openclaw pairing list telegram --json 2>/dev/null | jq -r '.requests[]?.code // empty')
  if [ -n "$CODES" ]; then
    for code in $CODES; do
      echo "Approving pairing: $code"
      openclaw pairing approve telegram "$code" 2>/dev/null
    done
    sleep 5
  else
    sleep 30
  fi
done
`
)

// clawAgent is the implementation of Agent for OpenClaw.
type clawAgent struct{}

// Compile-time checks
var _ Agent = (*clawAgent)(nil)
var _ TelegramConfigurer = (*clawAgent)(nil)

// NewClaw creates a new OpenClaw agent implementation.
func NewClaw() Agent {
	return &clawAgent{}
}

// Name returns the agent name.
func (c *clawAgent) Name() string {
	return "claw"
}

// SkipOnboarding modifies OpenClaw settings to disable gateway auth and enable
// the control UI. All other fields in the settings file are preserved.
func (c *clawAgent) SkipOnboarding(settings map[string][]byte, _ string) (map[string][]byte, error) {
	if settings == nil {
		settings = make(map[string][]byte)
	}

	var existingContent []byte
	var exists bool
	if existingContent, exists = settings[ClawConfigPath]; !exists {
		existingContent = []byte("{}")
	}

	var config map[string]interface{}
	if err := json.Unmarshal(existingContent, &config); err != nil {
		return nil, fmt.Errorf("failed to parse existing %s: %w", ClawConfigPath, err)
	}

	// Get or create the gateway map
	gateway, _ := config["gateway"].(map[string]interface{})
	if gateway == nil {
		gateway = make(map[string]interface{})
	}

	// Set auth mode to "none" (gateway.auth.mode)
	auth, _ := gateway["auth"].(map[string]interface{})
	if auth == nil {
		auth = make(map[string]interface{})
	}
	auth["mode"] = "none"
	gateway["auth"] = auth

	// Enable the control UI (gateway.controlUi.enabled)
	controlUi, _ := gateway["controlUi"].(map[string]interface{})
	if controlUi == nil {
		controlUi = make(map[string]interface{})
	}
	controlUi["enabled"] = true
	gateway["controlUi"] = controlUi

	config["gateway"] = gateway

	modifiedContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified %s: %w", ClawConfigPath, err)
	}

	settings[ClawConfigPath] = modifiedContent
	return settings, nil
}

// SkillsDir returns the container path under which skill directories are mounted for OpenClaw.
func (c *clawAgent) SkillsDir() string {
	return "$HOME/.openclaw/skills"
}

// SetMCPServers configures MCP servers in OpenClaw settings.
// It writes MCP server entries into openclaw.json under the "mcp.servers" key.
// Command-based servers use transport "stdio" with {command, args, env}.
// URL-based servers use transport "streamable-http" with {url, headers}.
// All other fields in the settings file are preserved.
// If mcp is nil, settings are returned unchanged.
func (c *clawAgent) SetMCPServers(settings map[string][]byte, mcp *workspace.McpConfiguration) (map[string][]byte, error) {
	if mcp == nil {
		return settings, nil
	}
	if settings == nil {
		settings = make(map[string][]byte)
	}

	var existingContent []byte
	var exists bool
	if existingContent, exists = settings[ClawConfigPath]; !exists {
		existingContent = []byte("{}")
	}

	var config map[string]interface{}
	if err := json.Unmarshal(existingContent, &config); err != nil {
		return nil, fmt.Errorf("failed to parse existing %s: %w", ClawConfigPath, err)
	}

	// Get or create the mcp map
	mcpConfig, _ := config["mcp"].(map[string]interface{})
	if mcpConfig == nil {
		mcpConfig = make(map[string]interface{})
	}

	// Get or create the servers map
	servers, _ := mcpConfig["servers"].(map[string]interface{})
	if servers == nil {
		servers = make(map[string]interface{})
	}

	if mcp.Commands != nil {
		for _, cmd := range *mcp.Commands {
			entry := map[string]interface{}{
				"transport": "stdio",
				"command":   cmd.Command,
				"args":      []string{},
				"env":       map[string]string{},
			}
			if cmd.Args != nil {
				entry["args"] = *cmd.Args
			}
			if cmd.Env != nil {
				entry["env"] = *cmd.Env
			}
			servers[cmd.Name] = entry
		}
	}

	if mcp.Servers != nil {
		for _, srv := range *mcp.Servers {
			entry := map[string]interface{}{
				"transport": "streamable-http",
				"url":       srv.Url,
			}
			if srv.Headers != nil {
				entry["headers"] = *srv.Headers
			}
			servers[srv.Name] = entry
		}
	}

	if len(servers) > 0 {
		mcpConfig["servers"] = servers
		config["mcp"] = mcpConfig
	}

	modifiedContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified %s: %w", ClawConfigPath, err)
	}

	settings[ClawConfigPath] = modifiedContent
	return settings, nil
}

// SetModel configures the model ID in OpenClaw settings.
// It sets agents.defaults.model in openclaw.json. OpenClaw uses provider/model
// format (e.g. "google/gemini-2.5-pro"). When the kdn provider::model format is
// used, it is converted to provider/model. Plain model IDs without a provider
// are passed through as-is.
// All other fields in the settings file are preserved.
func (c *clawAgent) SetModel(settings map[string][]byte, modelID string) (map[string][]byte, error) {
	if settings == nil {
		settings = make(map[string][]byte)
	}

	var existingContent []byte
	var exists bool
	if existingContent, exists = settings[ClawConfigPath]; !exists {
		existingContent = []byte("{}")
	}

	var config map[string]interface{}
	if err := json.Unmarshal(existingContent, &config); err != nil {
		return nil, fmt.Errorf("failed to parse existing %s: %w", ClawConfigPath, err)
	}

	// Get or create the agents map
	agents, _ := config["agents"].(map[string]interface{})
	if agents == nil {
		agents = make(map[string]interface{})
	}

	// Get or create the defaults map
	defaults, _ := agents["defaults"].(map[string]interface{})
	if defaults == nil {
		defaults = make(map[string]interface{})
	}

	provider, modelName, _ := kdnconfig.ParseModelID(modelID)
	if provider != "" {
		defaults["model"] = provider + "/" + modelName
	} else {
		defaults["model"] = modelID
	}
	agents["defaults"] = defaults
	config["agents"] = agents

	modifiedContent, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified %s: %w", ClawConfigPath, err)
	}

	settings[ClawConfigPath] = modifiedContent
	return settings, nil
}

// ConfigureTelegram writes the Telegram startup script into the agent settings.
// The script runs the OpenClaw gateway and auto-approves Telegram pairing requests.
func (c *clawAgent) ConfigureTelegram(settings map[string][]byte) (map[string][]byte, error) {
	if settings == nil {
		settings = make(map[string][]byte)
	}

	settings[ClawTelegramScriptPath] = []byte(clawTelegramScript)
	return settings, nil
}
