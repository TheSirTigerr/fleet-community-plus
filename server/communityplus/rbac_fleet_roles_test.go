package communityplus

import "testing"

func TestMaintainerRolesSeparateGlobalAndFleetScope(t *testing.T) {
	authorizer := Authorizer{}
	global := GlobalMaintainerRole()
	if !authorizer.Allowed(global, Request{Resource: ResourcePolicies, Action: ActionWrite, Scope: GlobalScope()}) {
		t.Fatal("global maintainer should write policies")
	}
	if !authorizer.Allowed(global, Request{Resource: ResourceSoftware, Action: ActionExecute, Scope: FleetScope(7)}) {
		t.Fatal("global maintainer should execute software operations")
	}
	if !authorizer.Allowed(global, Request{Resource: ResourceUsers, Action: ActionRead, Scope: GlobalScope()}) {
		t.Fatal("global maintainer should read users")
	}
	if authorizer.Allowed(global, Request{Resource: ResourceSettings, Action: ActionWrite, Scope: GlobalScope()}) {
		t.Fatal("global maintainer must not write global settings")
	}

	fleetRole, err := MaintainerRole(7)
	if err != nil {
		t.Fatal(err)
	}
	if !authorizer.Allowed(fleetRole, Request{Resource: ResourcePolicies, Action: ActionWrite, Scope: FleetScope(7)}) {
		t.Fatal("fleet maintainer should write policies in its fleet")
	}
	if authorizer.Allowed(fleetRole, Request{Resource: ResourcePolicies, Action: ActionWrite, Scope: FleetScope(8)}) {
		t.Fatal("fleet maintainer must not cross fleet scope")
	}
	if authorizer.Allowed(fleetRole, Request{Resource: ResourceUsers, Action: ActionRead, Scope: GlobalScope()}) {
		t.Fatal("fleet maintainer must not read global users")
	}
}

func TestTechnicianRolesCanOperateButNotConfigure(t *testing.T) {
	authorizer := Authorizer{}
	global := GlobalTechnicianRole()
	for _, resource := range []Resource{ResourceSoftware, ResourceScripts} {
		if !authorizer.Allowed(global, Request{Resource: resource, Action: ActionExecute, Scope: FleetScope(3)}) {
			t.Fatalf("global technician should execute %s operations", resource)
		}
		if authorizer.Allowed(global, Request{Resource: resource, Action: ActionWrite, Scope: FleetScope(3)}) {
			t.Fatalf("global technician must not configure %s", resource)
		}
	}
	if !authorizer.Allowed(global, Request{Resource: ResourcePolicies, Action: ActionRead, Scope: GlobalScope()}) {
		t.Fatal("global technician should read policies")
	}
	if authorizer.Allowed(global, Request{Resource: ResourcePolicies, Action: ActionWrite, Scope: GlobalScope()}) {
		t.Fatal("global technician must not write policies")
	}

	fleetRole, err := TechnicianRole(3)
	if err != nil {
		t.Fatal(err)
	}
	if !authorizer.Allowed(fleetRole, Request{Resource: ResourceScripts, Action: ActionExecute, Scope: FleetScope(3)}) {
		t.Fatal("fleet technician should execute scripts in its fleet")
	}
	if authorizer.Allowed(fleetRole, Request{Resource: ResourceScripts, Action: ActionExecute, Scope: FleetScope(4)}) {
		t.Fatal("fleet technician must not execute scripts in another fleet")
	}
}

func TestGitOpsRolesConfigureButNeverExecute(t *testing.T) {
	authorizer := Authorizer{}
	global := GlobalGitOpsRole()
	for _, resource := range []Resource{ResourceFleets, ResourcePolicies, ResourceSoftware, ResourceScripts, ResourceAutomations, ResourceSettings} {
		if !authorizer.Allowed(global, Request{Resource: resource, Action: ActionWrite, Scope: GlobalScope()}) {
			t.Fatalf("global gitops should write %s configuration", resource)
		}
	}
	for _, resource := range []Resource{ResourceSoftware, ResourceScripts} {
		if authorizer.Allowed(global, Request{Resource: resource, Action: ActionExecute, Scope: FleetScope(3)}) {
			t.Fatalf("global gitops must not execute %s operations", resource)
		}
	}
	if authorizer.Allowed(global, Request{Resource: ResourceAudit, Action: ActionRead, Scope: GlobalScope()}) {
		t.Fatal("global gitops must not gain activity/audit visibility from configuration access")
	}

	fleetRole, err := GitOpsRole(3)
	if err != nil {
		t.Fatal(err)
	}
	if !authorizer.Allowed(fleetRole, Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(3)}) {
		t.Fatal("fleet gitops should configure software in its fleet")
	}
	if authorizer.Allowed(fleetRole, Request{Resource: ResourceSoftware, Action: ActionWrite, Scope: FleetScope(4)}) {
		t.Fatal("fleet gitops must not cross fleet scope")
	}
	if !authorizer.Allowed(fleetRole, Request{Resource: ResourceSettings, Action: ActionRead, Scope: GlobalScope()}) {
		t.Fatal("fleet gitops should read global settings")
	}
	if authorizer.Allowed(fleetRole, Request{Resource: ResourceSettings, Action: ActionWrite, Scope: GlobalScope()}) {
		t.Fatal("fleet gitops must not write global settings")
	}
}
