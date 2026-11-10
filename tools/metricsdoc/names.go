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
	"go/ast"
	"go/token"
	"slices"
)

// binding is a declared name: a package-level declaration, or a local
// variable, constant, type or parameter.
type binding struct {
	value   ast.Expr // The value given in the declaration, nil when it is not known.
	changed bool     // Assigned again or had its address taken, so its value is unknown.
	isFunc  bool     // A package-level function.
}

// resolver walks the declarations of a package with Go's block scoping.
type resolver struct {
	pk     *pkg
	scopes []map[string]*binding // Innermost last.
	owner  string                // The function, method or package-level declaration being walked.
}

// resolveNames records the declaration that each identifier in pk refers to,
// marks the variables that are assigned again or have their address taken,
// and records the package-level functions that each function, method and
// package-level declaration refers to. The Probers map literal is skipped,
// because its entries are where the probers start.
func resolveNames(pk *pkg) {
	r := &resolver{pk: pk}
	for _, f := range pk.files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				r.enter(funcName(d), d)
				r.push()
				r.declareFields(d.Recv, d.Type.TypeParams, d.Type.Params, d.Type.Results)
				if d.Body != nil {
					r.walkList(d.Body.List)
				}
				r.pop()
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						r.enter(d.Tok.String()+" "+vs.Names[0].Name, vs)
						r.walk(vs.Type)
						for _, v := range vs.Values {
							r.walk(v)
						}
					}
				}
			}
		}
	}
}

func (r *resolver) enter(owner string, n ast.Node) {
	r.owner = owner
	if _, ok := r.pk.owners[owner]; !ok {
		r.pk.owners[owner] = n
	}
}

func (r *resolver) push() { r.scopes = append(r.scopes, map[string]*binding{}) }

func (r *resolver) pop() { r.scopes = r.scopes[:len(r.scopes)-1] }

func (r *resolver) declare(id *ast.Ident, value ast.Expr) {
	if id.Name != "_" {
		r.scopes[len(r.scopes)-1][id.Name] = &binding{value: value}
	}
}

func (r *resolver) declareFields(lists ...*ast.FieldList) {
	for _, fl := range lists {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			r.walk(f.Type)
			for _, id := range f.Names {
				r.declare(id, nil)
			}
		}
	}
}

func (r *resolver) lookup(name string) *binding {
	for _, scope := range slices.Backward(r.scopes) {
		if b, ok := scope[name]; ok {
			return b
		}
	}
	return r.pk.scope[name]
}

// use records what id refers to.
func (r *resolver) use(id *ast.Ident) {
	b := r.lookup(id.Name)
	if b == nil {
		return
	}
	r.pk.uses[id] = b
	if b.isFunc && !slices.Contains(r.pk.refs[r.owner], id.Name) {
		r.pk.refs[r.owner] = append(r.pk.refs[r.owner], id.Name)
	}
}

// change marks the variable that x is or is part of, as in v, v.f, v[i] or
// *v, as changed.
func (r *resolver) change(x ast.Expr) {
	for {
		switch v := x.(type) {
		case *ast.Ident:
			if b := r.lookup(v.Name); b != nil {
				b.changed = true
			}
			return
		case *ast.SelectorExpr:
			x = v.X
		case *ast.IndexExpr:
			x = v.X
		case *ast.StarExpr:
			x = v.X
		case *ast.ParenExpr:
			x = v.X
		default:
			return
		}
	}
}

func (r *resolver) walkList(stmts []ast.Stmt) {
	for _, s := range stmts {
		r.walk(s)
	}
}

// children walks the children of n.
func (r *resolver) children(n ast.Node) {
	ast.Inspect(n, func(c ast.Node) bool {
		if c == n {
			return true
		}
		r.walk(c)
		return false
	})
}

func (r *resolver) walk(n ast.Node) {
	switch x := n.(type) {
	case nil:
	case *ast.Ident:
		r.use(x)
	case *ast.SelectorExpr:
		r.walk(x.X) // x.Sel is a field, a method or a name in another package.
	case *ast.KeyValueExpr:
		// An identifier key is a struct field name, or a map key or array
		// index, which cannot be a function in code that runs.
		if _, ok := x.Key.(*ast.Ident); !ok {
			r.walk(x.Key)
		}
		r.walk(x.Value)
	case *ast.Field:
		r.walk(x.Type) // The names are field, method or parameter names.
	case *ast.CompositeLit:
		if x != r.pk.probers {
			r.children(x)
		}
	case *ast.FuncLit:
		r.push()
		r.declareFields(x.Type.Params, x.Type.Results)
		r.walkList(x.Body.List)
		r.pop()
	case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.CaseClause, *ast.CommClause:
		r.push()
		r.children(x)
		r.pop()
	case *ast.RangeStmt:
		r.walk(x.X)
		r.push()
		for _, v := range []ast.Expr{x.Key, x.Value} {
			if id, ok := v.(*ast.Ident); ok && x.Tok == token.DEFINE {
				r.declare(id, nil)
			} else if v != nil {
				r.walk(v)
				r.change(v)
			}
		}
		r.walk(x.Body)
		r.pop()
	case *ast.AssignStmt:
		for _, v := range x.Rhs {
			r.walk(v)
		}
		for i, lhs := range x.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || x.Tok != token.DEFINE {
				r.walk(lhs)
				r.change(lhs)
				continue
			}
			if b := r.scopes[len(r.scopes)-1][id.Name]; b != nil {
				b.changed = true // Already declared in this scope, so := assigns it.
				continue
			}
			var v ast.Expr
			if len(x.Lhs) == len(x.Rhs) {
				v = x.Rhs[i]
			}
			r.declare(id, v)
		}
	case *ast.IncDecStmt:
		r.walk(x.X)
		r.change(x.X)
	case *ast.UnaryExpr:
		r.walk(x.X)
		if x.Op == token.AND {
			r.change(x.X)
		}
	case *ast.ValueSpec:
		r.walk(x.Type)
		for _, v := range x.Values {
			r.walk(v)
		}
		for i, id := range x.Names {
			var v ast.Expr
			if len(x.Names) == len(x.Values) {
				v = x.Values[i]
			}
			r.declare(id, v)
		}
	case *ast.TypeSpec:
		r.declare(x.Name, nil)
		r.walk(x.Type)
	case *ast.LabeledStmt:
		r.walk(x.Stmt) // Labels are not variables.
	case *ast.BranchStmt:
	default:
		r.children(x)
	}
}
