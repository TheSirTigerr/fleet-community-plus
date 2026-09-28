package bootstrappackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fleetdm/fleet/v4/server/authz"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/stretchr/testify/require"
)

type activityRecorder struct {
	activities []fleet.ActivityDetails
}

func (r *activityRecorder) NewActivity(_ context.Context, _ *fleet.User, activity fleet.ActivityDetails) error {
	r.activities = append(r.activities, activity)
	return nil
}

func adminContext() context.Context {
	role := fleet.RoleAdmin
	return viewer.NewContext(context.Background(), viewer.Viewer{
		User: &fleet.User{GlobalRole: &role},
	})
}

func bootstrapFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "service", "testdata", "bootstrap-packages", name))
	require.NoError(t, err)
	return contents
}

func TestNewRequiresDependencies(t *testing.T) {
	ds := new(mock.Store)
	authorizer := authz.Must()
	activities := &activityRecorder{}

	_, err := New(nil, nil, authorizer, activities)
	require.ErrorContains(t, err, "datastore is nil")

	_, err = New(ds, nil, nil, activities)
	require.ErrorContains(t, err, "authorizer is nil")

	_, err = New(ds, nil, authorizer, nil)
	require.ErrorContains(t, err, "activity service is nil")
}

func TestUploadDryRunAndPersist(t *testing.T) {
	ctx := adminContext()
	ds := new(mock.Store)
	activities := &activityRecorder{}
	svc, err := New(ds, nil, authz.Must(), activities)
	require.NoError(t, err)

	pkgBytes := bootstrapFixture(t, "signed.pkg")
	var inserted *fleet.MDMAppleBootstrapPackage
	ds.InsertMDMAppleBootstrapPackageFunc = func(_ context.Context, bp *fleet.MDMAppleBootstrapPackage, store fleet.MDMBootstrapPackageStore) error {
		require.Nil(t, store)
		inserted = bp
		return nil
	}

	err = svc.Upload(ctx, "bootstrap.pkg", bytes.NewReader(pkgBytes), 0, true)
	require.NoError(t, err)
	require.Nil(t, inserted)
	require.Empty(t, activities.activities)

	err = svc.Upload(ctx, "bootstrap.pkg", bytes.NewReader(pkgBytes), 0, false)
	require.NoError(t, err)
	require.NotNil(t, inserted)
	require.Equal(t, "bootstrap.pkg", inserted.Name)
	require.Zero(t, inserted.TeamID)
	require.Equal(t, pkgBytes, inserted.Bytes)
	require.NotEmpty(t, inserted.Token)
	wantHash := sha256.Sum256(pkgBytes)
	require.Equal(t, wantHash[:], inserted.Sha256)
	require.Len(t, activities.activities, 1)
	_, ok := activities.activities[0].(fleet.ActivityTypeAddedBootstrapPackage)
	require.True(t, ok)
}

func TestUploadValidation(t *testing.T) {
	ctx := adminContext()
	ds := new(mock.Store)
	svc, err := New(ds, nil, authz.Must(), &activityRecorder{})
	require.NoError(t, err)

	err = svc.Upload(ctx, "bootstrap.pkg", nil, 0, false)
	require.Error(t, err)

	err = svc.Upload(ctx, "bootstrap.pkg", bytes.NewReader(nil), 0, false)
	require.Error(t, err)

	err = svc.Upload(ctx, "bootstrap.pkg", bytes.NewReader(bootstrapFixture(t, "unsigned.pkg")), 0, false)
	require.Error(t, err)

	err = svc.Upload(ctx, "bootstrap.pkg", bytes.NewReader(bootstrapFixture(t, "not-distribution-signed.pkg")), 0, false)
	require.ErrorContains(t, err, fleet.BootstrapPkgNotDistributionErrMsg)
}

func TestGetBytesRequiresToken(t *testing.T) {
	ds := new(mock.Store)
	svc, err := New(ds, nil, authz.Must(), &activityRecorder{})
	require.NoError(t, err)

	_, err = svc.GetBytes(context.Background(), "")
	require.Error(t, err)
}

func TestDeleteDryRunAndPersist(t *testing.T) {
	ctx := adminContext()
	ds := new(mock.Store)
	activities := &activityRecorder{}
	svc, err := New(ds, nil, authz.Must(), activities)
	require.NoError(t, err)

	ds.GetMDMAppleBootstrapPackageMetaFunc = func(_ context.Context, teamID uint) (*fleet.MDMAppleBootstrapPackage, error) {
		require.Zero(t, teamID)
		return &fleet.MDMAppleBootstrapPackage{Name: "bootstrap.pkg"}, nil
	}
	deleted := false
	ds.DeleteMDMAppleBootstrapPackageFunc = func(_ context.Context, teamID uint) error {
		require.Zero(t, teamID)
		deleted = true
		return nil
	}

	err = svc.Delete(ctx, nil, true)
	require.NoError(t, err)
	require.False(t, deleted)
	require.Empty(t, activities.activities)

	err = svc.Delete(ctx, nil, false)
	require.NoError(t, err)
	require.True(t, deleted)
	require.Len(t, activities.activities, 1)
	_, ok := activities.activities[0].(fleet.ActivityTypeDeletedBootstrapPackage)
	require.True(t, ok)
}

func TestDeletePropagatesMetadataError(t *testing.T) {
	ctx := adminContext()
	ds := new(mock.Store)
	svc, err := New(ds, nil, authz.Must(), &activityRecorder{})
	require.NoError(t, err)

	want := errors.New("metadata failed")
	ds.GetMDMAppleBootstrapPackageMetaFunc = func(context.Context, uint) (*fleet.MDMAppleBootstrapPackage, error) {
		return nil, want
	}

	err = svc.Delete(ctx, nil, false)
	require.ErrorIs(t, err, want)
}
