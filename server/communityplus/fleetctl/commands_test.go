package fleetctl

import "testing"

func TestCompatibilityCommands(t *testing.T) {
	command := UpdatesCommand()
	if command == nil || command.Name != "updates" || command.Action == nil {
		t.Fatalf("invalid updates command: %#v", command)
	}
	var destination string
	flag := LocalWixDirFlag(&destination)
	if flag == nil || flag.Names()[0] != "local-wix-dir" {
		t.Fatalf("invalid WiX flag: %#v", flag)
	}
}
