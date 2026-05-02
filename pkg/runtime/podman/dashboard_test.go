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
	"fmt"
	"strings"
	"testing"

	"github.com/openkaiden/kdn/pkg/runtime/podman/exec"
)

func TestGetURL_Success(t *testing.T) {
	t.Parallel()

	containerID := "abc123def456"
	fakeExec := exec.NewFake()
	fakeExec.OutputFunc = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "port" {
			return []byte("127.0.0.1:20254\n"), nil
		}
		return []byte(fmt.Sprintf("%s|running|kdn-test\n", containerID)), nil
	}

	p := newWithDeps(&fakeSystem{}, fakeExec).(*podmanRuntime)
	setupPodFiles(t, p, containerID, "my-project")

	url, err := p.GetURL(context.Background(), containerID)
	if err != nil {
		t.Fatalf("GetURL() failed: %v", err)
	}

	expected := "http://localhost:20254"
	if url != expected {
		t.Errorf("GetURL() = %q, want %q", url, expected)
	}
}

func TestGetURL_ReturnsCorrectPort(t *testing.T) {
	t.Parallel()

	containerID := "porttest123"
	fakeExec := exec.NewFake()
	fakeExec.OutputFunc = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "port" {
			return []byte("127.0.0.1:31337\n"), nil
		}
		return []byte(fmt.Sprintf("%s|running|kdn-test\n", containerID)), nil
	}

	p := newWithDeps(&fakeSystem{}, fakeExec).(*podmanRuntime)
	setupPodFiles(t, p, containerID, "port-test")

	url, err := p.GetURL(context.Background(), containerID)
	if err != nil {
		t.Fatalf("GetURL() failed: %v", err)
	}

	expected := "http://localhost:31337"
	if url != expected {
		t.Errorf("GetURL() = %q, want %q", url, expected)
	}
}

func TestGetURL_ContainerInfoFailure(t *testing.T) {
	t.Parallel()

	containerID := "abc123"
	fakeExec := exec.NewFake()
	fakeExec.OutputFunc = func(ctx context.Context, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("container not found")
	}

	p := newWithDeps(&fakeSystem{}, fakeExec).(*podmanRuntime)

	_, err := p.GetURL(context.Background(), containerID)
	if err == nil {
		t.Fatal("Expected error when getContainerInfo fails, got nil")
	}

	if !strings.Contains(err.Error(), "failed to get container info") {
		t.Errorf("Expected error to contain 'failed to get container info', got: %v", err)
	}
}

func TestGetURL_NotRunning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state string
	}{
		{"stopped container", "exited"},
		{"created container", "created"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			containerID := "abc123"
			fakeExec := exec.NewFake()
			fakeExec.OutputFunc = func(ctx context.Context, args ...string) ([]byte, error) {
				return []byte(fmt.Sprintf("%s|%s|kdn-test\n", containerID, tt.state)), nil
			}

			p := newWithDeps(&fakeSystem{}, fakeExec).(*podmanRuntime)

			_, err := p.GetURL(context.Background(), containerID)
			if err == nil {
				t.Fatal("Expected error for non-running container, got nil")
			}

			if !strings.Contains(err.Error(), "workspace is not running") {
				t.Errorf("Expected 'workspace is not running' error, got: %v", err)
			}
		})
	}
}

func TestGetURL_PodNameMissing(t *testing.T) {
	t.Parallel()

	containerID := "abc123"
	fakeExec := exec.NewFake()
	fakeExec.OutputFunc = func(ctx context.Context, args ...string) ([]byte, error) {
		return []byte(fmt.Sprintf("%s|running|kdn-test\n", containerID)), nil
	}

	p := newWithDeps(&fakeSystem{}, fakeExec).(*podmanRuntime)
	p.storageDir = t.TempDir()

	_, err := p.GetURL(context.Background(), containerID)
	if err == nil {
		t.Fatal("Expected error when pod name is missing, got nil")
	}

	if !strings.Contains(err.Error(), "failed to resolve pod name") {
		t.Errorf("Expected 'failed to resolve pod name' error, got: %v", err)
	}
}
