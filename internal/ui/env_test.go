package ui

import (
	"os"
	"testing"
)

func TestIsCI_WithCIVar(t *testing.T) {
	os.Setenv("CI", "true")
	defer os.Unsetenv("CI")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when CI=true")
	}
}

func TestIsCI_WithGitHubActions(t *testing.T) {
	os.Setenv("GITHUB_ACTIONS", "true")
	defer os.Unsetenv("GITHUB_ACTIONS")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when GITHUB_ACTIONS=true")
	}
}

func TestIsCI_WithJenkins(t *testing.T) {
	os.Setenv("JENKINS_HOME", "/var/jenkins")
	defer os.Unsetenv("JENKINS_HOME")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when JENKINS_HOME is set")
	}
}

func TestIsCI_WithTravis(t *testing.T) {
	os.Setenv("TRAVIS", "true")
	defer os.Unsetenv("TRAVIS")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when TRAVIS=true")
	}
}

func TestIsCI_WithCircleCI(t *testing.T) {
	os.Setenv("CIRCLECI", "true")
	defer os.Unsetenv("CIRCLECI")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when CIRCLECI=true")
	}
}

func TestIsCI_WithGitLabCI(t *testing.T) {
	os.Setenv("GITLAB_CI", "true")
	defer os.Unsetenv("GITLAB_CI")

	if !IsCI() {
		t.Error("Expected IsCI() to return true when GITLAB_CI=true")
	}
}

func TestIsCI_NoCI(t *testing.T) {
	// Clear all CI variables to ensure clean state
	ciVars := []string{"CI", "GITHUB_ACTIONS", "JENKINS_HOME", "TRAVIS", "CIRCLECI", "GITLAB_CI", "BUILDKITE", "DRONE", "TF_BUILD"}
	for _, v := range ciVars {
		os.Unsetenv(v)
	}

	if IsCI() {
		t.Error("Expected IsCI() to return false when no CI variables are set")
	}
}
