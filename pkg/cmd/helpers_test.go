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

package cmd

import "testing"

func TestAdaptExampleForAlias(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		example     string
		originalCmd string
		aliasCmd    string
		want        string
	}{
		{
			name: "replaces command in simple example",
			example: `# List all workspaces
kdn workspace list`,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want: `# List all workspaces
kdn list`,
		},
		{
			name: "replaces command with flags",
			example: `# List workspaces in JSON format
kdn workspace list --output json`,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want: `# List workspaces in JSON format
kdn list --output json`,
		},
		{
			name: "replaces multiple occurrences",
			example: `# List all workspaces
kdn workspace list

# List in JSON format
kdn workspace list --output json

# List using short flag
kdn workspace list -o json`,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want: `# List all workspaces
kdn list

# List in JSON format
kdn list --output json

# List using short flag
kdn list -o json`,
		},
		{
			name: "does not replace in comments",
			example: `# Use workspace list to see all workspaces
kdn workspace list`,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want: `# Use workspace list to see all workspaces
kdn list`,
		},
		{
			name: "replaces remove command",
			example: `# Remove workspace by ID
kdn workspace remove abc123`,
			originalCmd: "workspace remove",
			aliasCmd:    "remove",
			want: `# Remove workspace by ID
kdn remove abc123`,
		},
		{
			name:        "handles empty example",
			example:     ``,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want:        ``,
		},
		{
			name: "preserves indentation",
			example: `# List all workspaces
kdn workspace list

# Another example
	kdn workspace list --output json`,
			originalCmd: "workspace list",
			aliasCmd:    "list",
			want: `# List all workspaces
kdn list

# Another example
	kdn list --output json`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := AdaptExampleForAlias(tt.example, tt.originalCmd, tt.aliasCmd)
			if got != tt.want {
				t.Errorf("AdaptExampleForAlias() mismatch:\nGot:\n%s\n\nWant:\n%s", got, tt.want)
			}
		})
	}
}
