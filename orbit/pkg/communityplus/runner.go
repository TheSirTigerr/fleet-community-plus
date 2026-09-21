package communityplus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type Client interface {
	GetCommunityPlusDeployment(string) (*fleet.CommunityPlusInstallPlan, error)
	SaveCommunityPlusDeploymentResult(*fleet.CommunityPlusDeploymentResult) error
}

type Runner struct {
	client Client
}

func NewRunner(client Client) *Runner { return &Runner{client: client} }

func (r *Runner) Run(c *fleet.OrbitConfig) error {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
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

func execute(ctx context.Context, p *fleet.CommunityPlusInstallPlan) (int, string, error) {
	if p == nil {
		return 1, "", fmt.Errorf("missing Community+ deployment plan")
	}
	if err := p.Validate(); err != nil {
		return 1, "", err
	}
	if p.TargetPlatform() != runtime.GOOS {
		return 1, "", fmt.Errorf("Community+ deployment target %q does not match endpoint %q", p.TargetPlatform(), runtime.GOOS)
	}
	switch runtime.GOOS {
	case "windows":
		return executeWindows(ctx, p)
	case "darwin":
		return executeMacOS(ctx, p)
	default:
		return 1, "", fmt.Errorf("unsupported Community+ endpoint platform %q", runtime.GOOS)
	}
}

func executeWindows(ctx context.Context, p *fleet.CommunityPlusInstallPlan) (int, string, error) {
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

func executeMacOS(ctx context.Context, p *fleet.CommunityPlusInstallPlan) (int, string, error) {
	if p.InstallerType != "pkg" {
		return 1, "", fmt.Errorf("unsupported Community+ macOS installer type %q", p.InstallerType)
	}
	dir, err := os.MkdirTemp("", "communityplus-")
	if err != nil {
		return 1, "", err
	}
	defer os.RemoveAll(dir)
	pkg := filepath.Join(dir, "installer.pkg")
	if err := downloadVerifiedInstaller(ctx, p.InstallerURL, p.SHA256, pkg); err != nil {
		return 1, "", err
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output), nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(output), nil
	}
	return 1, string(output), err
}

func downloadVerifiedInstaller(ctx context.Context, rawURL, expectedSHA, destination string) error {
	client := &http.Client{
		Timeout: 30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("Community+ installer redirect must remain HTTPS")
			}
			if len(via) >= 10 {
				return fmt.Errorf("Community+ installer has too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("create Community+ installer request: %w", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download Community+ installer: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Community+ installer returned HTTP %d", res.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create Community+ installer file: %w", err)
	}
	h := sha256.New()
	const maxInstallerBytes int64 = 4 << 30
	written, copyErr := io.Copy(io.MultiWriter(file, h), io.LimitReader(res.Body, maxInstallerBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("write Community+ installer: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close Community+ installer: %w", closeErr)
	}
	if written > maxInstallerBytes {
		return fmt.Errorf("Community+ installer exceeds 4 GiB limit")
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedSHA) {
		return fmt.Errorf("Community+ installer SHA-256 mismatch")
	}
	return nil
}
