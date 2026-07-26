package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type buildEvidence struct {
	Module      string
	Version     string
	VCSRevision string
	VCSModified string
	BuildDate   string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lattice-plugin-manifest-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printVersion := fs.Bool("version", false, "print validator build evidence and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	build := currentBuildEvidence()
	if *printVersion {
		writeBuildEvidence(stdout, build)
		return 0
	}
	if fs.NArg() == 0 {
		writeBuildEvidence(stdout, build)
		fmt.Fprintln(stderr, "usage: lattice-plugin-manifest-check <manifest.json> [manifest.json...]")
		return 2
	}

	writeBuildEvidence(stdout, build)
	failed := false
	for _, path := range fs.Args() {
		manifest, err := checkManifest(path)
		if err != nil {
			fmt.Fprintf(stderr, "%s: invalid: %v\n", path, err)
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "%s: ok id=%s version=%s schema=%s\n",
			path, manifest.ID, manifest.Version, schemaLabel(manifest.Schema))
	}
	if failed {
		return 1
	}
	return 0
}

func checkManifest(path string) (plugin.Manifest, error) {
	manifest, err := readManifest(path)
	if err != nil {
		return plugin.Manifest{}, err
	}
	if err := plugin.ValidateManifest(manifest); err != nil {
		return plugin.Manifest{}, err
	}
	return manifest, nil
}

func readManifest(path string) (plugin.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return plugin.Manifest{}, fmt.Errorf("read: %w", err)
	}
	return plugin.DecodeManifest(data)
}

func currentBuildEvidence() buildEvidence {
	out := buildEvidence{
		Module:      "github.com/LatticeNet/lattice-server",
		Version:     version,
		VCSRevision: commit,
		VCSModified: "unknown",
		BuildDate:   date,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	if info.Main.Path != "" {
		out.Module = info.Main.Path
	}
	if out.Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		out.Version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if out.VCSRevision == "unknown" {
				out.VCSRevision = setting.Value
			}
		case "vcs.modified":
			out.VCSModified = setting.Value
		}
	}
	return out
}

func writeBuildEvidence(w io.Writer, build buildEvidence) {
	fmt.Fprintf(w, "lattice-plugin-manifest-check server_module=%s server_version=%s server_commit=%s build_date=%s vcs_modified=%s\n",
		build.Module, build.Version, build.VCSRevision, build.BuildDate, build.VCSModified)
}

func schemaLabel(schema string) string {
	if schema == "" {
		return "legacy"
	}
	return schema
}
