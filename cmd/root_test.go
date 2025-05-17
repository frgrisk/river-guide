package cmd

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestExtractResourceGroupName(t *testing.T) {
	vmID := "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM"
	got := extractResourceGroupName(vmID)
	want := "myResourceGroup"
	if got != want {
		t.Errorf("extractResourceGroupName(%q) = %q, want %q", vmID, got, want)
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"PowerState/running", string(types.InstanceStateNameRunning)},
		{"PowerState/stopped", string(types.InstanceStateNameStopped)},
		{"PowerState/deallocated", string(types.InstanceStateNameStopped)},
		{"PowerState/unknown", string(types.InstanceStateNamePending)},
	}

	for _, tt := range tests {
		if got := normalizeStatus(tt.input); got != tt.want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
