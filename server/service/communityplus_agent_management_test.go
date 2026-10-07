package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

func TestCommunityPlusPolicyScriptRetryQueuesRequest(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{
		ds:     ds,
		logger: slog.New(slog.DiscardHandler),
	}

	scriptID := uint(9)
	policyID := uint(10)
	attempt := 1
	host := &fleet.Host{ID: 42}
	result := &fleet.HostScriptResult{
		HostID:         host.ID,
		ScriptID:       &scriptID,
		PolicyID:       &policyID,
		AttemptNumber:  &attempt,
		ScriptContents: "echo repair",
	}

	var queued *fleet.HostScriptRequestPayload
	ds.NewHostScriptExecutionRequestFunc = func(_ context.Context, request *fleet.HostScriptRequestPayload) (*fleet.HostScriptResult, error) {
		copy := *request
		queued = &copy
		return &fleet.HostScriptResult{HostID: request.HostID, ScriptID: request.ScriptID, PolicyID: request.PolicyID}, nil
	}

	require.NoError(t, svc.retryPolicyAutomationScript(context.Background(), host, result))
	require.NotNil(t, queued)
	require.Equal(t, host.ID, queued.HostID)
	require.Equal(t, scriptID, *queued.ScriptID)
	require.Equal(t, policyID, *queued.PolicyID)
	require.Equal(t, "echo repair", queued.ScriptContents)
	require.False(t, queued.DeferActivation)
}

func TestCommunityPlusPolicyScriptRetryRespectsLimitAndPolicyState(t *testing.T) {
	ds := new(mock.Store)
	svc := &Service{
		ds:     ds,
		logger: slog.New(slog.DiscardHandler),
	}
	host := &fleet.Host{ID: 42}
	scriptID := uint(9)
	policyID := uint(10)

	t.Run("retries while policy still fails", func(t *testing.T) {
		attempt := 1
		ds.IsPolicyFailingFunc = func(_ context.Context, gotPolicyID, gotHostID uint) (bool, error) {
			require.Equal(t, policyID, gotPolicyID)
			require.Equal(t, host.ID, gotHostID)
			return true, nil
		}
		retry, err := svc.shouldRetryPolicyAutomationScript(context.Background(), host, &fleet.HostScriptResult{
			ScriptID: &scriptID, PolicyID: &policyID, AttemptNumber: &attempt,
		})
		require.NoError(t, err)
		require.True(t, retry)
	})

	t.Run("does not retry after policy passes", func(t *testing.T) {
		attempt := 1
		ds.IsPolicyFailingFunc = func(context.Context, uint, uint) (bool, error) {
			return false, nil
		}
		retry, err := svc.shouldRetryPolicyAutomationScript(context.Background(), host, &fleet.HostScriptResult{
			ScriptID: &scriptID, PolicyID: &policyID, AttemptNumber: &attempt,
		})
		require.NoError(t, err)
		require.False(t, retry)
	})

	t.Run("does not exceed retry cap", func(t *testing.T) {
		attempt := fleet.MaxPolicyAutomationRetries
		retry, err := svc.shouldRetryPolicyAutomationScript(context.Background(), host, &fleet.HostScriptResult{
			ScriptID: &scriptID, PolicyID: &policyID, AttemptNumber: &attempt,
		})
		require.NoError(t, err)
		require.False(t, retry)
	})
}
