package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	maintained_apps "github.com/fleetdm/fleet/v4/ee/maintained-apps"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/ingesters/homebrew"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/ingesters/winget"
	"github.com/fleetdm/fleet/v4/ee/maintained-apps/sources"
	"github.com/fleetdm/fleet/v4/pkg/file"
	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
)

func main() {
	slugPtr := flag.String("slug", "", "app slug")
	debugPtr := flag.Bool("debug", false, "enable debug logging")
	inputRootPtr := flag.String("input-root", "ee/maintained-apps/inputs", "directory containing homebrew and winget catalog sources")
	outputDirPtr := flag.String("output-dir", maintained_apps.OutputPath, "directory for generated catalog manifests")
	checkPtr := flag.Bool("check", false, "validate the catalog without writing output files")
	fetchSourcesPtr := flag.Bool("fetch-sources", false, "download and verify pinned public source files before generating the catalog")
	flag.Parse()
	ctx := context.Background()
	logLevel := slog.LevelInfo
	if *debugPtr {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	options := catalogOptions{
		Slug:      *slugPtr,
		InputRoot: *inputRootPtr,
		OutputDir: *outputDirPtr,
		CheckOnly: *checkPtr,
	}
	if *fetchSourcesPtr {
		if options.CheckOnly {
			logger.ErrorContext(ctx, "maintained app ingestion failed", "err", "--fetch-sources cannot be combined with --check")
			os.Exit(1)
		}
		if err := sources.Sync(ctx, options.InputRoot); err != nil {
			logger.ErrorContext(ctx, "maintained app source download failed", "err", err)
			os.Exit(1)
		}
	}
	if err := run(ctx, logger, options); err != nil {
		logger.ErrorContext(ctx, "maintained app ingestion failed", "err", err)
		os.Exit(1)
	}
}

type catalogOptions struct {
	Slug      string
	InputRoot string
	OutputDir string
	CheckOnly bool
}

type catalogIngester struct {
	name   string
	ingest maintained_apps.Ingester
}

func run(ctx context.Context, logger *slog.Logger, options catalogOptions) error {
	if options.InputRoot == "" || options.OutputDir == "" {
		return fmt.Errorf("input-root and output-dir must not be empty")
	}
	logger.InfoContext(ctx, "starting Community+ maintained app ingestion", "check_only", options.CheckOnly)

	ingesters := []catalogIngester{
		{name: "homebrew", ingest: homebrew.IngestApps},
		{name: "winget", ingest: winget.IngestApps},
	}
	var apps []*maintained_apps.FMAManifestApp
	seen := make(map[string]string)
	for _, ingester := range ingesters {
		inputDir := filepath.Join(options.InputRoot, ingester.name)
		imported, err := ingester.ingest(ctx, logger, inputDir, options.Slug)
		if err != nil {
			return fmt.Errorf("ingest %s catalog: %w", ingester.name, err)
		}
		for _, app := range imported {
			if app.IsEmpty() {
				return fmt.Errorf("%s catalog returned an incomplete app", ingester.name)
			}
			if previous, ok := seen[app.Slug]; ok {
				return fmt.Errorf("duplicate catalog slug %q in %s and %s", app.Slug, previous, ingester.name)
			}
			if err := validateCategories(ctx, app); err != nil {
				return err
			}
			seen[app.Slug] = ingester.name
			apps = append(apps, app)
		}
	}

	if options.CheckOnly {
		logger.InfoContext(ctx, "Community+ maintained app catalog is valid", "apps", len(apps))
		return nil
	}
	if err := os.MkdirAll(options.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create catalog output directory: %w", err)
	}
	for _, app := range apps {
		if err := processOutput(ctx, app, options.OutputDir); err != nil {
			return err
		}
	}
	return ensureAppsList(options.OutputDir)
}

func processOutput(ctx context.Context, app *maintained_apps.FMAManifestApp, outputDir string) error {
	appCopy := *app
	appCopy.UniqueIdentifier = "" // App-list metadata must not leak into individual app manifests.

	outFile := maintained_apps.FMAManifestFile{
		Versions: []*maintained_apps.FMAManifestApp{&appCopy},
		Refs:     map[string]string{appCopy.UninstallScriptRef: appCopy.UninstallScript, appCopy.InstallScriptRef: appCopy.InstallScript},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(outFile); err != nil {
		return ctxerr.Wrap(ctx, err, "marshaling output app manifest")
	}
	outBytes := buf.Bytes()

	outDir := path.Join(outputDir, app.SlugAppName())

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return ctxerr.Wrap(ctx, err)
	}
	outFilePath := path.Join(outputDir, fmt.Sprintf("%s.json", app.Slug))
	outFileExists, err := file.Exists(outFilePath)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "checking if output json file exists")
	}

	// Overwrite the file unless frozen, since right now we're only caring about 1 version (latest). If we
	// care about previous data, it will be in our Git history.
	if !app.Frozen || !outFileExists {
		if err := writeFileAtomic(outFilePath, outBytes); err != nil {
			return ctxerr.Wrap(ctx, err, "writing output json file")
		}
	}
	if err := updateAppsListFile(ctx, app, outputDir); err != nil {
		return ctxerr.Wrap(ctx, err, "updating apps list file")
	}

	return nil
}

// Match types in frontend/interfaces/software.ts
var allowedCategories = map[string]struct{}{
	"Browsers":        {},
	"Communication":   {},
	"Developer tools": {},
	"Productivity":    {},
	"Security":        {},
	"Support":         {},
	"Utilities":       {},
}

func allowedCategoriesString() string {
	cats := make([]string, 0, len(allowedCategories))
	for c := range allowedCategories {
		cats = append(cats, c)
	}
	slices.Sort(cats)
	return strings.Join(cats, ", ")
}

// validateCategories ensures every category on the app is one of the supported values.
func validateCategories(ctx context.Context, app *maintained_apps.FMAManifestApp) error {
	for _, c := range app.DefaultCategories {
		if _, ok := allowedCategories[c]; !ok {
			return ctxerr.New(ctx, fmt.Sprintf(
				"invalid category %q for slug %s (allowed: %s)",
				c, app.Slug, allowedCategoriesString(),
			))
		}
	}
	return nil
}

func updateAppsListFile(ctx context.Context, outApp *maintained_apps.FMAManifestApp, outputDir string) error {
	appListFilePath := path.Join(outputDir, "apps.json")
	inputJson, err := os.ReadFile(appListFilePath)
	if err != nil && !os.IsNotExist(err) {
		return ctxerr.Wrap(ctx, err, "reading output apps list file")
	}

	outputAppsFile := maintained_apps.FMAListFile{Version: 2}
	if len(inputJson) > 0 {
		if err := json.Unmarshal(inputJson, &outputAppsFile); err != nil {
			return ctxerr.Wrap(ctx, err, "unmarshaling output apps list file")
		}
	}
	if outputAppsFile.Version == 0 {
		outputAppsFile.Version = 2
	}

	var found bool
	for _, a := range outputAppsFile.Apps {
		if a.Slug == outApp.Slug {
			found = true
			break
		}
	}

	if !found {
		platform := outApp.Platform()
		if platform == "" {
			return ctxerr.New(ctx, fmt.Sprintf("invalid platform found for slug %s", outApp.Slug))
		}

		outputAppsFile.Apps = append(outputAppsFile.Apps, maintained_apps.FMAListFileApp{
			Name:             outApp.Name,
			Slug:             outApp.Slug,
			Platform:         platform,
			UniqueIdentifier: outApp.UniqueIdentifier,
		})

		// Keep existing order
		slices.SortFunc(outputAppsFile.Apps, func(a, b maintained_apps.FMAListFileApp) int { return strings.Compare(a.Slug, b.Slug) })

		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(outputAppsFile); err != nil {
			return ctxerr.Wrap(ctx, err, "marshaling updated output apps file")
		}
		updatedFile := buf.Bytes()

		if err := writeFileAtomic(appListFilePath, updatedFile); err != nil {
			return ctxerr.Wrap(ctx, err, "writing updated output apps file")
		}
	}

	return nil
}

func ensureAppsList(outputDir string) error {
	appListFilePath := path.Join(outputDir, "apps.json")
	if _, err := os.Stat(appListFilePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check output apps list: %w", err)
	}
	data, err := json.MarshalIndent(maintained_apps.FMAListFile{Version: 2, Apps: []maintained_apps.FMAListFileApp{}}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal empty output apps list: %w", err)
	}
	return writeFileAtomic(appListFilePath, append(data, '\n'))
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".catalog-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
