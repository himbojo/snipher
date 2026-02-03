package ui

import "os"

// IsCI detects if the application is running in a CI/CD environment
// by checking for common CI environment variables
func IsCI() bool {
	ciVars := []string{
		"CI",             // Generic CI indicator
		"GITHUB_ACTIONS", // GitHub Actions
		"JENKINS_HOME",   // Jenkins
		"TRAVIS",         // Travis CI
		"CIRCLECI",       // CircleCI
		"GITLAB_CI",      // GitLab CI
		"BUILDKITE",      // Buildkite
		"DRONE",          // Drone CI
		"TF_BUILD",       // Azure Pipelines
	}

	for _, envVar := range ciVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}

	return false
}
