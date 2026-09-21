package fleet

import ("fmt"; "strings")
type CommunityPlusWindowsInstallPlan struct { DeploymentID string `json:"deployment_id"`; PackageID string `json:"package_identifier"`; Version string `json:"version"`; InstallerURL string `json:"installer_url"`; SHA256 string `json:"sha256"`; InstallerType string `json:"installer_type"`; ProductCode string `json:"product_code,omitempty"` }
func (p CommunityPlusWindowsInstallPlan) Validate() error { if p.DeploymentID==""||p.PackageID==""||p.Version==""||!strings.HasPrefix(p.InstallerURL,"https://")||len(p.SHA256)!=64{return fmt.Errorf("invalid Community+ Windows install plan")}; for _,c:=range p.SHA256 {if !((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')){return fmt.Errorf("invalid Community+ installer hash")}}; if p.InstallerType!="msi"&&p.InstallerType!="msix"&&p.InstallerType!="msixbundle"{return fmt.Errorf("unsupported Community+ installer type")};return nil }
type OrbitGetCommunityPlusDeploymentRequest struct { OrbitNodeKey string `json:"orbit_node_key"`; DeploymentID string `json:"deployment_id"` }
func(r *OrbitGetCommunityPlusDeploymentRequest)SetOrbitNodeKey(k string){r.OrbitNodeKey=k};func(r *OrbitGetCommunityPlusDeploymentRequest)OrbitHostNodeKey()string{return r.OrbitNodeKey}
type OrbitGetCommunityPlusDeploymentResponse struct { Err error `json:"error,omitempty"`; Plan *CommunityPlusWindowsInstallPlan `json:"plan,omitempty"`};func(r OrbitGetCommunityPlusDeploymentResponse)Error()error{return r.Err}
type CommunityPlusDeploymentResult struct { DeploymentID string `json:"deployment_id"`; ExitCode int `json:"exit_code"`; Output string `json:"output,omitempty"` }
type OrbitPostCommunityPlusDeploymentResultRequest struct { OrbitNodeKey string `json:"orbit_node_key"`; *CommunityPlusDeploymentResult };func(r *OrbitPostCommunityPlusDeploymentResultRequest)SetOrbitNodeKey(k string){r.OrbitNodeKey=k};func(r *OrbitPostCommunityPlusDeploymentResultRequest)OrbitHostNodeKey()string{return r.OrbitNodeKey}
type OrbitPostCommunityPlusDeploymentResultResponse struct { Err error `json:"error,omitempty"`};func(r OrbitPostCommunityPlusDeploymentResultResponse)Error()error{return r.Err}
