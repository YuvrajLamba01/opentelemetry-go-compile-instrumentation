// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"

	"go.opentelemetry.io/otelc/tool/ex"
	"go.opentelemetry.io/otelc/tool/internal/rule"
	"go.opentelemetry.io/otelc/tool/util"
)

// load loads the matched rules from the build temp directory.
// TODO: Shared memory across all sub-processes is possible
func (ip *instrumentPhase) load() ([]*rule.InstRuleSet, error) {
	f := util.GetMatchedRuleFile()
	content, err := os.ReadFile(f)
	if os.IsNotExist(err) {
		return nil, ex.Newf("no instrumentation configuration found (%s does not exist); "+
			"run `otelc setup` in the module directory before building with `-toolexec`, "+
			"or build with `otelc go build` instead", f)
	}
	if err != nil {
		return nil, ex.Wrapf(err, "failed to read file %s", f)
	}
	rset := make([]*rule.InstRuleSet, 0)
	err = json.Unmarshal(content, &rset)
	if err != nil {
		return nil, ex.Wrapf(err, "failed to unmarshal JSON")
	}

	ip.Debug("Load matched rule sets", "path", f)
	return rset, nil
}

// anyRuleSetHasIgnoredCallFiles reports whether any package in this build has
// a //otelc:ignore comment above a call, found during setup.
func anyRuleSetHasIgnoredCallFiles(allSet []*rule.InstRuleSet) bool {
	for _, rset := range allSet {
		if len(rset.IgnoredCallFiles) > 0 {
			return true
		}
	}
	return false
}

// loadImportNames loads the import name table. A missing file is not
// an error, since the table only improves a fallback guess.
func loadImportNames() (map[string]string, error) {
	f := util.GetImportNamesFile()
	content, err := os.ReadFile(f)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, ex.Wrapf(err, "failed to read file %s", f)
	}
	names := make(map[string]string)
	if jsonErr := json.Unmarshal(content, &names); jsonErr != nil {
		return nil, ex.Wrapf(jsonErr, "failed to unmarshal JSON")
	}
	return names, nil
}

// match matches the rules with the compile command.
func (ip *instrumentPhase) match(allSet []*rule.InstRuleSet, args []string) *rule.InstRuleSet {
	// Several packages can share an import path, such as every main package
	// of a build, so a rule set only matches a compile that holds the files
	// its rules were matched in. A go test run can also compile one package
	// twice, with and without its _test.go files, so the rule set must come
	// from the same kind of compile as this one.
	importPath := util.FindFlagValue(args, "-p")
	util.Assert(importPath != "", "sanity check")
	isTest := util.IsTestBuild(args)
	compiled := make(map[string]bool, len(args))
	for _, arg := range args {
		if !util.IsGoFile(arg) {
			continue
		}
		if abs, err := filepath.Abs(arg); err == nil {
			compiled[abs] = true
		}
	}
	var matches []*rule.InstRuleSet
	for _, rset := range allSet {
		if rset.ModulePath == importPath && rset.IsTest == isTest && ip.compilesRuleFiles(rset, compiled) {
			ip.Debug("Match rule set", "set", rset)
			matches = append(matches, rset)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return mergeRuleSets(matches)
}

type fileRuleKey struct {
	name         string
	file         string
	path         string
	resolvedPath string
}

func appendRuleMap[T any](dst, src map[string][]T) {
	for file, rules := range src {
		dst[file] = append(dst[file], rules...)
	}
}

func appendUniqueFileRules(
	dst []*rule.InstFileRule,
	seen map[fileRuleKey]bool,
	src []*rule.InstFileRule,
) []*rule.InstFileRule {
	for _, fr := range src {
		if fr == nil {
			continue
		}
		key := fileRuleKey{
			name:         fr.Name,
			file:         fr.File,
			path:         fr.Path,
			resolvedPath: fr.ResolvedPath,
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, fr)
	}
	return dst
}

func appendUniqueStrings(dst []string, seen map[string]bool, src []string) []string {
	for _, s := range src {
		if seen[s] {
			continue
		}
		seen[s] = true
		dst = append(dst, s)
	}
	return dst
}

func mergeRuleSets(matches []*rule.InstRuleSet) *rule.InstRuleSet {
	merged := rule.NewInstRuleSet(matches[0].ModulePath)
	merged.IsTest = matches[0].IsTest
	seenFileRules := make(map[fileRuleKey]bool)
	seenIgnored := make(map[string]bool)
	for _, rset := range matches {
		if merged.PackageName == "" && rset.PackageName != "" {
			merged.PackageName = rset.PackageName
		}
		maps.Copy(merged.CgoFileMap, rset.CgoFileMap)
		appendRuleMap(merged.RawRules, rset.RawRules)
		appendRuleMap(merged.FuncRules, rset.FuncRules)
		appendRuleMap(merged.StructRules, rset.StructRules)
		appendRuleMap(merged.CallRules, rset.CallRules)
		appendRuleMap(merged.LitRules, rset.LitRules)
		appendRuleMap(merged.DirectiveRules, rset.DirectiveRules)
		appendRuleMap(merged.DeclRules, rset.DeclRules)
		merged.FileRules = appendUniqueFileRules(merged.FileRules, seenFileRules, rset.FileRules)
		merged.IgnoredCallFiles = appendUniqueStrings(merged.IgnoredCallFiles, seenIgnored, rset.IgnoredCallFiles)
	}
	return merged
}

// compilesRuleFiles reports whether every file rset has rules for is in
// compiled, using the same cgo file mapping as instrument.
func (ip *instrumentPhase) compilesRuleFiles(rset *rule.InstRuleSet, compiled map[string]bool) bool {
	_, files := groupRules(ip.workDir, rset)
	for _, file := range files {
		if !compiled[file] {
			return false
		}
	}
	return true
}
