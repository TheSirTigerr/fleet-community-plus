package communityplus

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type Client interface {
	GetCommunityPlusDeployment(string) (*fleet.CommunityPlusWindowsInstallPlan, error)
	SaveCommunityPlusDeploymentResult(*fleet.CommunityPlusDeploymentResult) error
}

type Runner struct {
	client Client
}

func NewRunner(client Client) *Runner { return &Runner{client: client} }

func (r *Runner) Run(c *fleet.OrbitConfig) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	for _, id := range c.Notifications.PendingCommunityPlusDeploymentIDs {
		plan, err := r.client.GetCommunityPlusDeployment(id)
		result := &fleet.CommunityPlusDeploymentResult{DeploymentID: id, ExitCode: 1}
		if err == nil {
			result.ExitCode, result.Output, err = execute(context.Background(), plan)
		}
		if err != nil && result.Output == "" {
			result.Output = err.Error()
		}
		if err = r.client.SaveCommunityPlusDeploymentResult(result); err != nil {
			return fmt.Errorf("save Community+ deployment result: %w", err)
		}
	}
	return nil
}

func successfulWindowsInstallerExitCode(code int) bool {
	return code == 0 || code == 1641 || code == 3010
}

func execute(ctx context.Context, p *fleet.CommunityPlusWindowsInstallPlan) (int, string, error) {
	if p == nil {
		return 1, "", fmt.Errorf("missing Community+ deployment plan")
	}
	if err := p.Validate(); err != nil {
		return 1, "", err
	}
	script := fmt.Sprintf("$ErrorActionPreference='Stop'\n$file=Join-Path $env:TEMP ('communityplus-'+ '%s' + '-%s')\nInvoke-WebRequest -Uri '%s' -OutFile $file -UseBasicParsing\nif ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne '%s') { throw 'Installer SHA-256 mismatch' }\nif ('%s' -eq 'msi') { $existing=Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq '%s' }; if ($existing -and $existing.DisplayVersion -eq '%s') { exit 0 }; $x=Start-Process msiexec.exe -ArgumentList @('/i',$file,'/qn','/norestart') -Wait -PassThru -NoNewWindow; exit $x.ExitCode }; Add-AppxPackage -Path $file -ForceApplicationShutdown", p.DeploymentID, p.InstallerType, p.InstallerURL, strings.ToLower(p.SHA256), p.InstallerType, p.ProductCode, p.Version)
	dir, err := os.MkdirTemp("", "communityplus-")
	if err != nil {
		return 1, "", err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "install.ps1")
	if err = os.WriteFile(file, []byte(script), 0600); err != nil {
		return 1, "", err
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output), nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		code := exitErr.ExitCode()
		if successfulWindowsInstallerExitCode(code) {
			return 0, string(output), nil
		}
		return code, string(output), nil
	}
	return 1, string(output), err
}
