package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlanCompilersUseAScopedResolver is the structural half of the fix for the
// defect class this package shipped twice: a handler authorizes the caller on
// the identifier it was given, then dereferences a second identifier on the way
// to building its answer, and that second dereference is never checked.
//
// Both instances went through a compiler. Every compiler in the tree turns
// records into a config and takes a NodeResolver to reach the records, so the
// resolver is the single choke point where the second dereference happens. This
// test reads the package source and fails when a compiler is handed anything
// other than a resolver that carries a principal.
//
// It is a source-level test on purpose. A runtime test can only prove the paths
// it exercises; this one covers every call site that exists, including one
// written tomorrow, and it fails at review time rather than after a disclosure.
//
// Adding a compiler to compilersRequiringScopedResolver is the maintenance
// cost, and it is the right cost: a new function that assembles node data into
// an artefact should have to say so here.
func TestPlanCompilersUseAScopedResolver(t *testing.T) {
	// Package-qualified compiler entry points whose resolver argument decides
	// which nodes' data lands in the artefact, mapped to the zero-based index of
	// that argument. netguard.Compile takes a struct, handled separately below.
	compilersRequiringScopedResolver := map[string]int{
		"netpolicy.NormalizePolicy":          1,
		"netpolicy.CompileEgressRuleset":     1,
		"netpolicy.CompileEgressPlan":        1,
		"netpolicy.CompileIngressInputRules": 1,
	}
	// Struct-literal compilers: the field that carries the resolver.
	structCompilers := map[string]string{
		"netguard.Compile":        "Resolve",
		"netguard.CompileRuleset": "Resolve",
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := qualifiedName(call.Fun)
			if idx, ok := compilersRequiringScopedResolver[callee]; ok {
				checked++
				if idx >= len(call.Args) {
					t.Errorf("%s: %s called with %d args, expected a resolver at %d",
						fset.Position(call.Pos()), callee, len(call.Args), idx)
					return true
				}
				if !isScopedResolverExpr(call.Args[idx]) {
					t.Errorf("%s: %s is handed %q, which is not a resolver built by "+
						"nodeResolverFor/nodeResolverOver (or the declared systemNodeResolver escape "+
						"hatch). An unscoped lookup here puts nodes the caller cannot read into the "+
						"artefact it gets back. See authz_nodeset.go.",
						fset.Position(call.Pos()), callee, exprString(call.Args[idx]))
				}
				return true
			}
			if field, ok := structCompilers[callee]; ok && len(call.Args) == 1 {
				lit, ok := call.Args[0].(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != field {
						continue
					}
					checked++
					if !isScopedResolverExpr(kv.Value) {
						t.Errorf("%s: %s gets %s: %q, which is not a resolver built by "+
							"nodeResolverFor/nodeResolverOver (or the declared systemNodeResolver "+
							"escape hatch). See authz_nodeset.go.",
							fset.Position(kv.Pos()), callee, field, exprString(kv.Value))
					}
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no compiler call sites found; this test has stopped guarding anything, " +
			"which most likely means a compiler was renamed without updating the lists above")
	}
	t.Logf("checked %d compiler call sites", checked)
}

// isScopedResolverExpr reports whether e is the Resolve method of a resolver
// built through one of the constructors in authz_nodeset.go, or a local
// variable named resolver holding one. It matches on shape rather than on
// types, which keeps the test independent of the type checker; the shape is
// narrow enough that nothing else in the package matches it by accident.
func isScopedResolverExpr(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Resolve" {
		return false
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		// resolver.Resolve, where resolver came from a constructor. The
		// constructors are the only thing in this package that produces a value
		// with a Resolve method, so the name is sufficient here.
		return x.Name == "resolver"
	case *ast.CallExpr:
		// s.nodeResolverFor(...).Resolve
		name := qualifiedName(x.Fun)
		return name == "s.nodeResolverFor" ||
			name == "s.nodeResolverOver" ||
			name == "s.systemNodeResolver" ||
			name == "s.systemNodeResolverOver"
	}
	return false
}

// TestUnscopedNodeResolverIsGone pins the removal of the bare resolver. It
// existed as s.resolveNode and was the shared root of both shipped defects:
// a method that looked like a helper and silently handed out any node in the
// fleet. Deleting it turned every unsafe call site into a compile error, which
// is why the conversion could be exhaustive rather than best-effort.
func TestUnscopedNodeResolverIsGone(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "func (s *Server) resolveNode(") {
			t.Errorf("%s reintroduces the unscoped resolver. Use nodeResolverFor with a "+
				"scope, or systemNodeResolver with a written reason if the output genuinely "+
				"never reaches a caller.", name)
		}
	}
}

func qualifiedName(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		if ident, ok := e.(*ast.Ident); ok {
			return ident.Name
		}
		return ""
	}
	if x, ok := sel.X.(*ast.Ident); ok {
		return x.Name + "." + sel.Sel.Name
	}
	return sel.Sel.Name
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return qualifiedName(v)
	case *ast.CallExpr:
		return qualifiedName(v.Fun) + "(...)"
	case *ast.FuncLit:
		return "func literal"
	}
	return "expression"
}
