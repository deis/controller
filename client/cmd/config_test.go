package cmd

import (
	"os"
	"os/exec"
	"testing"
)

// Fancy way for testing processes exit unsuccessfully.
// See https://talks.golang.org/2014/testing.slide#23
func TestParseConfig(t *testing.T) {
	if os.Getenv("TEST_BAD_CONFIG") == "1" {
		parseConfig([]string{"FOO=bar", "CAR star"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestParseConfig")
	cmd.Env = append(os.Environ(), "TEST_BAD_CONFIG=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}
