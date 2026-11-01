// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	promPath     = "github.com/prometheus/client_golang/prometheus"
	promautoPath = "github.com/prometheus/client_golang/prometheus/promauto"
	versionPath  = "github.com/prometheus/client_golang/prometheus/collectors/version"

	// proberDir holds the probers. Its metrics are attributed to probers by
	// following calls from the entry points in the Probers map.
	proberDir = "prober"
	// handlerFunc is the prober function that creates the metrics returned
	// by every probe.
	handlerFunc = "Handler"
)

// exporterDirs are the package directories whose metrics are served on /metrics.
var exporterDirs = []string{".", "config"}

// buildContext selects the files to read: the ones built for linux/amd64, so
// that the result does not depend on the platform the generator runs on. A
// file that is left out and defines metrics is an error.
var buildContext = func() build.Context {
	c := build.Default
	c.GOOS, c.GOARCH, c.CgoEnabled = "linux", "amd64", false
	return c
}()

// dynamicLabels lists the metrics whose label names come from the module
// configuration, with the configuration field that sets them.
var dynamicLabels = map[string]string{
	"probe_expect_info": "query_response[].labels",
}

// buildInfo describes the metric created by the client_golang version
// collector, see prometheus/collectors/version/version.go. If a client_golang
// update changes it, TestCatalogCoversRuntimeMetrics fails and this needs
// updating; make metrics-docs alone does not fix it.
var buildInfo = struct {
	help   string
	labels []string
}{
	help:   "A metric with a constant '1' value labeled by version, revision, branch, goversion from which %s was built, and the goos and goarch for the build.",
	labels: []string{"version", "revision", "branch", "goversion", "goos", "goarch", "tags"},
}

var (
	// metricCtor matches the client_golang constructors the generator reads.
	metricCtor = regexp.MustCompile(`^New(Gauge|Counter|Histogram|Summary)(Vec)?$`)
	// otherCtor matches client_golang constructors that define metrics in a
	// way the generator cannot read.
	otherCtor = regexp.MustCompile(`^New(Desc|(Gauge|Counter|Untyped)Func|Untyped(Vec)?)$`)
)

// site is a place in the source that defines a metric.
type site struct {
	Pos  string // File and line, relative to the repository root.
	Func string // Enclosing function, empty at package level.
}

// metric is a metric name and everything the generated tables show about it.
type metric struct {
	Name       string
	Type       string
	Help       string
	Labels     []string // In definition order.
	LabelsFrom string   // Configuration field that sets the label names, if they are not fixed.
	Exporter   bool     // Served on /metrics instead of /probe.
	EveryProbe bool     // Created by the probe handler, whatever the prober.
	Probers    []string // Probers that can return the metric, in Probers map order.
	Sites      []site
}

// catalog is the result of extract.
type catalog struct {
	Probers []string  // In the order of the Probers map.
	Metrics []*metric // Sorted by name.
}

type pkg struct {
	dir     string
	files   []*ast.File
	scope   map[string]*binding     // Package-level declarations, except init functions.
	uses    map[*ast.Ident]*binding // The declaration each identifier refers to, if it is in this package.
	refs    map[string][]string     // The package-level functions each function, method or package-level declaration refers to.
	owners  map[string]ast.Node     // The declaration behind each key of refs.
	probers *ast.CompositeLit       // The Probers map literal.
}

type extractor struct {
	root string
	fset *token.FileSet
	pkgs map[string]*pkg
	defs []*metric // One per definition site, merged by name later.
	errs []string
}

// extract parses the non-test Go files under root that are built for
// linux/amd64 and returns every metric the exporter can expose.
//
// It fails, with the file and line, on a definition it cannot read from the
// source: a name, help or label list that is not a constant, options or
// labels that are assigned again or have their address taken, a constructor
// other than the ones metricCtor matches, and code that defines metrics but
// is reached other than through package-level functions from the Probers map.
// It does not follow values through other variables or function calls, so it
// does not see a label slice changed through an alias, or a function value
// stored in a variable and called by another prober. The runtime test checks
// what it extracts against what the probers return.
func extract(root string) (*catalog, error) {
	e := &extractor{root: root, fset: token.NewFileSet(), pkgs: map[string]*pkg{}}
	if err := e.parse(); err != nil {
		return nil, err
	}
	var entries []proberEntry
	for _, dir := range slices.Sorted(maps.Keys(e.pkgs)) {
		pk := e.pkgs[dir]
		if dir == proberDir {
			entries = e.probers(pk)
		}
		resolveNames(pk)
		e.collect(pk)
	}
	c := e.resolve(entries)
	if len(e.errs) > 0 {
		slices.Sort(e.errs)
		return nil, errors.New(strings.Join(slices.Compact(e.errs), "\n"))
	}
	return c, nil
}

func (e *extractor) parse() error {
	return filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			// Skip the directories the go command ignores.
			if p != e.root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(e.fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		built, err := buildContext.MatchFile(filepath.Dir(p), name)
		if err != nil {
			return err
		}
		if !built {
			e.checkExcluded(f)
			return nil
		}
		rel, err := filepath.Rel(e.root, filepath.Dir(p))
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(rel)
		pk := e.pkgs[dir]
		if pk == nil {
			pk = &pkg{dir: dir, scope: map[string]*binding{}, uses: map[*ast.Ident]*binding{}, refs: map[string][]string{}, owners: map[string]ast.Node{}}
			e.pkgs[dir] = pk
		}
		pk.files = append(pk.files, f)
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name != "init" {
					pk.scope[d.Name.Name] = &binding{isFunc: true}
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for i, id := range s.Names {
							b := &binding{}
							if len(s.Names) == len(s.Values) {
								b.value = s.Values[i]
							}
							pk.scope[id.Name] = b
						}
					case *ast.TypeSpec:
						pk.scope[s.Name.Name] = &binding{}
					}
				}
			}
		}
		return nil
	})
}

// checkExcluded reports the metrics defined in f, a file that is not built
// for buildContext.
func (e *extractor) checkExcluded(f *ast.File) {
	s := &scope{pk: &pkg{}, imports: fileImports(f)}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && definesMetric(s.clientGolang(call)) {
			e.errorf(call, "metric defined in a file that is not built for %s/%s, the only platform the metrics doc generator reads", buildContext.GOOS, buildContext.GOARCH)
		}
		return true
	})
}

func (e *extractor) errorf(n ast.Node, format string, args ...any) {
	e.errs = append(e.errs, e.pos(n)+": "+fmt.Sprintf(format, args...))
}

func (e *extractor) pos(n ast.Node) string {
	p := e.fset.Position(n.Pos())
	rel, err := filepath.Rel(e.root, p.Filename)
	if err != nil {
		rel = p.Filename
	}
	return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), p.Line)
}

// scope resolves identifiers in one file of a package.
type scope struct {
	pk      *pkg
	imports map[string]string // Local name to import path.
}

// value returns the value id was declared with, or nil when it is unknown:
// id is not declared in the package, was declared without a value, or was
// assigned again or had its address taken.
func (s *scope) value(id *ast.Ident) ast.Expr {
	if b := s.pk.uses[id]; b != nil && !b.changed {
		return b.value
	}
	return nil
}

// isPkg reports whether x refers to the import with the given path.
func (s *scope) isPkg(x ast.Expr, importPath string) bool {
	id, ok := x.(*ast.Ident)
	return ok && s.pk.uses[id] == nil && s.imports[id.Name] == importPath
}

// clientGolang returns the import path of the client_golang package and the
// name of the function that call calls. The path is empty when call calls a
// method or a function of another package. The methods of promauto.With(r)
// count as functions of promauto.
func (s *scope) clientGolang(call *ast.CallExpr) (importPath, name string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	if inner, ok := sel.X.(*ast.CallExpr); ok {
		if p, n := s.clientGolang(inner); p == promautoPath && n == "With" {
			return promautoPath, sel.Sel.Name
		}
		return "", sel.Sel.Name
	}
	for _, p := range []string{promPath, promautoPath, versionPath} {
		if s.isPkg(sel.X, p) {
			return p, sel.Sel.Name
		}
	}
	return "", sel.Sel.Name
}

// definesMetric reports whether the client_golang function name of the
// package importPath creates a metric.
func definesMetric(importPath, name string) bool {
	if importPath == versionPath {
		return name == "NewCollector"
	}
	return importPath != "" && (metricCtor.MatchString(name) || otherCtor.MatchString(name))
}

func fileImports(f *ast.File) map[string]string {
	imports := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = p
	}
	return imports
}

func (e *extractor) collect(pk *pkg) {
	for _, f := range pk.files {
		s := &scope{pk: pk, imports: fileImports(f)}
		for _, decl := range f.Decls {
			fn := ""
			var body ast.Node = decl
			if fd, ok := decl.(*ast.FuncDecl); ok {
				if fd.Body == nil {
					continue
				}
				fn = funcName(fd)
				body = fd.Body
			}
			ast.Inspect(body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					e.call(s, fn, call)
				}
				return true
			})
		}
	}
}

// funcName returns the name of fd, prefixed with the receiver type for a method.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil {
		return fd.Name.Name
	}
	return recvType(fd.Recv.List[0].Type) + "." + fd.Name.Name
}

func recvType(t ast.Expr) string {
	switch x := t.(type) {
	case *ast.StarExpr:
		return recvType(x.X)
	case *ast.IndexExpr:
		return recvType(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}

// call records the metric defined by call, if it is a metric constructor.
func (e *extractor) call(s *scope, fn string, call *ast.CallExpr) {
	importPath, ctor := s.clientGolang(call)
	if importPath == versionPath && ctor == "NewCollector" {
		e.versionCollector(s, fn, call)
		return
	}
	isProm := importPath == promPath || importPath == promautoPath
	m := metricCtor.FindStringSubmatch(ctor)
	switch {
	case isProm && otherCtor.MatchString(ctor):
		e.errorf(call, "%s is not supported by the metrics doc generator", ctor)
		return
	case m == nil:
		return
	case !isProm:
		e.errorf(call, "%s is called on something other than the prometheus or promauto package, the metrics doc generator cannot read it", ctor)
		return
	}
	def := &metric{Type: strings.ToLower(m[1]), Sites: []site{{Pos: e.pos(call), Func: fn}}}
	if len(call.Args) == 0 {
		e.errorf(call, "%s has no options argument", ctor)
		return
	}
	opts := e.opts(s, call.Args[0])
	if opts == nil {
		e.errorf(call, "cannot resolve the options of %s to a prometheus.*Opts literal, or they are changed later", ctor)
		return
	}
	var namespace, subsystem string
	for _, elt := range opts.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			e.errorf(elt, "metric options must use field names")
			return
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			continue
		}
		var dst *string
		switch key.Name {
		case "Namespace":
			dst = &namespace
		case "Subsystem":
			dst = &subsystem
		case "Name":
			dst = &def.Name
		case "Help":
			dst = &def.Help
		case "ConstLabels":
			e.errorf(kv, "ConstLabels are not supported by the metrics doc generator")
			return
		default:
			continue
		}
		v, ok := e.str(s, kv.Value)
		if !ok {
			e.errorf(kv, "%s is not a constant string", key.Name)
			return
		}
		*dst = v
	}
	if def.Name == "" {
		e.errorf(call, "metric has no name")
		return
	}
	def.Name = buildFQName(namespace, subsystem, def.Name)
	if m[2] == "Vec" {
		if len(call.Args) < 2 {
			e.errorf(call, "%s has no label names argument", ctor)
			return
		}
		labels, ok := e.strs(s, call.Args[1])
		from, dynamic := dynamicLabels[def.Name]
		switch {
		case ok:
			def.Labels = labels
		case dynamic:
			def.LabelsFrom = from
		default:
			e.errorf(call, "label names of %s are not a constant []string, or they are changed later; if they come from the configuration, add the metric to dynamicLabels", def.Name)
			return
		}
	}
	e.add(s, def)
}

func (e *extractor) versionCollector(s *scope, fn string, call *ast.CallExpr) {
	if len(call.Args) != 1 {
		e.errorf(call, "version collector options are not supported by the metrics doc generator")
		return
	}
	program, ok := e.str(s, call.Args[0])
	if !ok {
		e.errorf(call, "version collector program name is not a constant string")
		return
	}
	e.add(s, &metric{
		Name:   program + "_build_info",
		Type:   "gauge",
		Help:   fmt.Sprintf(buildInfo.help, program),
		Labels: buildInfo.labels,
		Sites:  []site{{Pos: e.pos(call), Func: fn}},
	})
}

func (e *extractor) add(s *scope, def *metric) {
	def.Exporter = slices.Contains(exporterDirs, s.pk.dir)
	if !def.Exporter && s.pk.dir != proberDir {
		e.errs = append(e.errs, fmt.Sprintf("%s: metric %s is defined in package directory %q, the metrics doc generator only knows %q",
			def.Sites[0].Pos, def.Name, s.pk.dir, append([]string{proberDir}, exporterDirs...)))
		return
	}
	e.defs = append(e.defs, def)
}

// opts resolves x to a prometheus.*Opts composite literal.
func (e *extractor) opts(s *scope, x ast.Expr) *ast.CompositeLit {
	switch v := x.(type) {
	case *ast.CompositeLit:
		if sel, ok := v.Type.(*ast.SelectorExpr); ok && s.isPkg(sel.X, promPath) && strings.HasSuffix(sel.Sel.Name, "Opts") {
			return v
		}
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			return e.opts(s, v.X)
		}
	case *ast.ParenExpr:
		return e.opts(s, v.X)
	case *ast.Ident:
		if def := s.value(v); def != nil {
			return e.opts(s, def)
		}
	}
	return nil
}

// str evaluates x as a constant string: a literal, a named constant or a
// concatenation of those.
func (e *extractor) str(s *scope, x ast.Expr) (string, bool) {
	switch v := x.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			str, err := strconv.Unquote(v.Value)
			return str, err == nil
		}
	case *ast.ParenExpr:
		return e.str(s, v.X)
	case *ast.Ident:
		if def := s.value(v); def != nil {
			return e.str(s, def)
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			a, okA := e.str(s, v.X)
			b, okB := e.str(s, v.Y)
			return a + b, okA && okB
		}
	}
	return "", false
}

// strs evaluates x as a []string literal of constant strings.
func (e *extractor) strs(s *scope, x ast.Expr) ([]string, bool) {
	switch v := x.(type) {
	case *ast.Ident:
		if def := s.value(v); def != nil {
			return e.strs(s, def)
		}
	case *ast.CompositeLit:
		at, ok := v.Type.(*ast.ArrayType)
		if !ok {
			return nil, false
		}
		if elt, ok := at.Elt.(*ast.Ident); !ok || elt.Name != "string" {
			return nil, false
		}
		out := []string{}
		for _, el := range v.Elts {
			str, ok := e.str(s, el)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	}
	return nil, false
}

func buildFQName(namespace, subsystem, name string) string {
	parts := []string{}
	for _, p := range []string{namespace, subsystem, name} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "_")
}

// resolve attributes the definitions to probers and merges them by name.
func (e *extractor) resolve(entries []proberEntry) *catalog {
	c := &catalog{}
	reach := map[string][]string{} // Function to the probers that reach it.
	if pk := e.pkgs[proberDir]; pk != nil {
		for _, p := range entries {
			c.Probers = append(c.Probers, p.name)
			for _, fn := range reachable(pk, p.fn) {
				reach[fn] = append(reach[fn], p.name)
			}
		}
		e.checkRefs(pk)
	}

	byName := map[string]*metric{}
	for _, def := range e.defs {
		site := def.Sites[0]
		if !def.Exporter {
			if site.Func == handlerFunc {
				def.EveryProbe = true
			} else {
				def.Probers = slices.Clone(reach[site.Func])
				if len(def.Probers) == 0 {
					e.errs = append(e.errs, fmt.Sprintf("%s: metric %s is not reachable from any prober in the Probers map; the metrics doc generator only follows references to package-level functions", site.Pos, def.Name))
					continue
				}
			}
		}
		m, ok := byName[def.Name]
		if !ok {
			byName[def.Name] = def
			continue
		}
		if m.Type != def.Type || m.Help != def.Help || !slices.Equal(m.Labels, def.Labels) || m.LabelsFrom != def.LabelsFrom || m.Exporter != def.Exporter || m.EveryProbe != def.EveryProbe {
			e.errs = append(e.errs, fmt.Sprintf("%s: metric %s is also defined at %s with a different type, help, labels or scope", site.Pos, def.Name, m.Sites[0].Pos))
			continue
		}
		m.Sites = append(m.Sites, site)
		for _, p := range def.Probers {
			if !slices.Contains(m.Probers, p) {
				m.Probers = append(m.Probers, p)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		m := byName[name]
		slices.SortFunc(m.Probers, func(a, b string) int {
			return slices.Index(c.Probers, a) - slices.Index(c.Probers, b)
		})
		c.Metrics = append(c.Metrics, m)
	}
	return c
}

// reachable returns the package-level functions that the functions in from
// refer to, directly or through other package-level functions, including the
// ones in from.
func reachable(pk *pkg, from ...string) []string {
	seen := map[string]bool{}
	var out []string
	for queue := slices.Clone(from); len(queue) > 0; queue = queue[1:] {
		if fn := queue[0]; !seen[fn] {
			seen[fn] = true
			out = append(out, fn)
			queue = append(queue, pk.refs[fn]...)
		}
	}
	return out
}

// checkRefs reports the methods, init functions, package-level declarations
// and the probe handler that lead to a function that defines metrics. The
// probers of a metric come from following references from the Probers map
// through package-level functions only, so they could be incomplete for a
// metric that is also reached in one of these other ways.
func (e *extractor) checkRefs(pk *pkg) {
	defines := map[string]string{} // Function to a metric it defines.
	for _, def := range e.defs {
		if fn := def.Sites[0].Func; !def.Exporter && defines[fn] == "" {
			defines[fn] = def.Name
		}
	}
	for _, owner := range slices.Sorted(maps.Keys(pk.refs)) {
		if b := pk.scope[owner]; b != nil && b.isFunc && owner != handlerFunc {
			continue
		}
		for _, fn := range reachable(pk, pk.refs[owner]...) {
			if name := defines[fn]; name != "" {
				e.errorf(pk.owners[owner], "%s leads to %s, which defines %s; the metrics doc generator only follows references from the Probers map through package-level functions, so it cannot tell which probers return the metric", owner, fn, name)
				break
			}
		}
	}
}

type proberEntry struct{ name, fn string }

// probers returns the entries of the map[string]ProbeFn literal in pk.
func (e *extractor) probers(pk *pkg) []proberEntry {
	var entries []proberEntry
	found := 0
	for _, f := range pk.files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, ok := cl.Type.(*ast.MapType)
			if !ok {
				return true
			}
			if v, ok := mt.Value.(*ast.Ident); !ok || v.Name != "ProbeFn" {
				return true
			}
			found++
			pk.probers = cl
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				var key *ast.BasicLit
				var fn *ast.Ident
				if ok {
					key, _ = kv.Key.(*ast.BasicLit)
					fn, _ = kv.Value.(*ast.Ident)
				}
				if key == nil || fn == nil || pk.scope[fn.Name] == nil || !pk.scope[fn.Name].isFunc {
					e.errorf(elt, "Probers entries must map a string literal to a package-level function")
					continue
				}
				name, _ := strconv.Unquote(key.Value)
				entries = append(entries, proberEntry{name: name, fn: fn.Name})
			}
			return true
		})
	}
	if found != 1 {
		e.errs = append(e.errs, fmt.Sprintf("%s: found %d map[string]ProbeFn literals, want exactly 1", proberDir, found))
		return nil
	}
	return entries
}
