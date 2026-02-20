package swagger

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var goKeywords = map[string]bool{
	"break": true, "default": true, "func": true, "interface": true, "select": true,
	"case": true, "defer": true, "go": true, "map": true, "struct": true,
	"chan": true, "else": true, "goto": true, "package": true, "switch": true,
	"const": true, "fallthrough": true, "if": true, "range": true, "type": true,
	"continue": true, "for": true, "import": true, "return": true, "var": true,
}

type Config struct {
	Title        string            `json:"title"`
	Version      string            `json:"version"`
	PathGroup    map[string]string `json:"pathGroup"`
	defaultGroup string            `json:"defaultGroup"`
}

var defaultConfig = Config{}

func Main(output string, cfgFile string, group bool, inputFile string) {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var swagger map[string]interface{}
	err = json.Unmarshal(data, &swagger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}
	if cfgFile != "" {
		cfgData, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
		err = json.Unmarshal(cfgData, &defaultConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config JSON: %v\n", err)
			os.Exit(1)
		}
	}

	if group {
		outputDir := output
		if fi, err := os.Stat(output); err == nil && !fi.IsDir() {
			ext := filepath.Ext(output)
			base := strings.TrimSuffix(output, ext)
			outputDir = base + "_api"
		} else if os.IsNotExist(err) {
			if filepath.Ext(output) != "" {
				outputDir = strings.TrimSuffix(output, filepath.Ext(output)) + "_api"
			}
		}
		err = generateGroupedFiles(swagger, outputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating grouped files: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully converted %s to files in %s\n", inputFile, outputDir)
	} else {
		content, err := generateAPIContent(swagger, nil, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating API: %v\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(output, []byte(content), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully converted %s to %s\n", inputFile, output)
	}
}

// --------------------------------------------------------------------
// Parsing and grouping
// --------------------------------------------------------------------

type ParsedSwagger struct {
	Info    map[string]interface{}
	Paths   map[string]interface{}
	Schemas map[string]interface{}
}

func parseSwagger(swagger map[string]interface{}) *ParsedSwagger {
	parsed := &ParsedSwagger{
		Info:    map[string]interface{}{},
		Paths:   map[string]interface{}{},
		Schemas: map[string]interface{}{},
	}
	if info, ok := swagger["info"].(map[string]interface{}); ok {
		parsed.Info = info
	}
	if paths, ok := swagger["paths"].(map[string]interface{}); ok {
		parsed.Paths = paths
	}
	if components, ok := swagger["components"].(map[string]interface{}); ok {
		if schemas, ok := components["schemas"].(map[string]interface{}); ok {
			parsed.Schemas = schemas
		}
	}
	if defs, ok := swagger["definitions"].(map[string]interface{}); ok {
		parsed.Schemas = defs
	}
	return parsed
}

func getGroupPathFromPath(path string) string {
	components := strings.Split(path, "/")
	groupPath := ""
	if len(components) < 2 {
		groupPath = "default"
	} else {
		groupPath = strings.Join(components[:len(components)-1], "/")
	}
	for k, v := range defaultConfig.PathGroup {
		//fmt.Printf("test group %v=>%v\n", groupPath, k)
		if strings.HasPrefix(groupPath, k) {
			t := strings.ReplaceAll(groupPath, k, v)
			//fmt.Printf("match group %v=>%v=>%s\n", groupPath, k, t)
			return t
		}
	}
	if defaultConfig.defaultGroup != "" {
		target := defaultConfig.defaultGroup + "/" + strings.TrimPrefix(groupPath, "/")
		fmt.Printf("path:%v->%s\n", path, target)
		return target
	}
	fmt.Printf("path:%v->%s\n", path, groupPath)
	return groupPath
}

func groupPathsByService(paths map[string]interface{}) map[string]map[string]interface{} {
	groups := make(map[string]map[string]interface{})
	groups["default"] = make(map[string]interface{})

	for path, pathItem := range paths {
		groupPath := getGroupPathFromPath(path)
		if _, ok := groups[groupPath]; !ok {
			groups[groupPath] = make(map[string]interface{})
		}
		groups[groupPath][path] = pathItem
	}
	return groups
}

func sanitizeIdentifier(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}

// --------------------------------------------------------------------
// Type conversion and name simplification
// --------------------------------------------------------------------

func swaggerTypeToGoZeroType(typ, format string) string {
	switch format {
	case "int32":
		return "int32"
	case "int64":
		return "int64"
	case "float":
		return "float32"
	case "double":
		return "float64"
	case "byte":
		return "byte"
	case "binary", "date", "date-time", "password":
		return "string"
	}
	switch typ {
	case "string":
		return "string"
	case "integer":
		return "int64"
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		return "[]"
	case "object", "any":
		return "string"
	case "null", "void":
		return "interface{}"
	default:
		return "string"
	}
}

type NameSimplifier struct {
}

func NewNameSimplifier() *NameSimplifier {
	return &NameSimplifier{}
}
func (ns *NameSimplifier) Simplify(typeName string, refNameStat map[string]int) string {
	parts := strings.Split(typeName, ".")
	base := parts[len(parts)-1]

	if goKeywords[strings.ToLower(base)] {
		var unique strings.Builder
		for _, p := range parts {
			unique.WriteString(capitalize(p))
		}
		name := unique.String()
		return name
	}
	if len(parts) == 1 {
		return capitalize(base)
	}
	if v, ok := refNameStat[base]; ok && v > 1 {
		lastTwo := capitalize(parts[len(parts)-2]) + capitalize(base)
		return lastTwo
	} else {
		return capitalize(base)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return string(unicode.ToUpper(r[0])) + string(r[1:])
}

// --------------------------------------------------------------------
// Type declaration generation
// --------------------------------------------------------------------

func generateTypeDeclarations(schemas map[string]interface{}, refNameStat map[string]int, dumpTypes map[string]bool) (string, map[string]string, error) {
	var allLines, nestedLines []string
	nameMap := make(map[string]string)
	for name := range schemas {
		simplifier := NewNameSimplifier()
		nameMap[name] = simplifier.Simplify(name, refNameStat)
	}
	sortedOrigNames := make([]string, 0)
	for origName := range schemas {
		sortedOrigNames = append(sortedOrigNames, origName)
	}
	sort.Strings(sortedOrigNames)
	for _, origName := range sortedOrigNames {
		schema, ok := schemas[origName].(map[string]interface{})
		if !ok {
			continue
		}
		if _, ok := schema["$ref"]; ok {
			continue
		}
		if origName == "interface" {
			continue
		}
		simpleName := nameMap[origName]
		if _, ok := dumpTypes[simpleName]; ok {
			continue
		}
		dumpTypes[simpleName] = true
		fmt.Printf("+ Type: %s\n", simpleName)
		lines := []string{fmt.Sprintf("type %s {", simpleName)}
		if props, ok := schema["properties"].(map[string]interface{}); ok {
			var propNames []string
			for propName := range props {
				propNames = append(propNames, propName)
			}
			sort.Strings(propNames)
			for _, propName := range propNames {
				propIf := props[propName]
				prop, ok := propIf.(map[string]interface{})
				if !ok {
					continue
				}
				goType := "string"
				if ref, ok := prop["$ref"].(string); ok {
					refName := lastPartOfRef(ref)
					if refName == "interface" {
						goType = "map[string]interface{}"
					} else {
						goType = nameMap[refName]
					}
				} else if items, ok := prop["items"].(map[string]interface{}); ok {
					if itemRef, ok := items["$ref"].(string); ok {
						refName := lastPartOfRef(itemRef)
						if refName == "interface" {
							goType = "[]map[string]interface{}"
						} else {
							goType = "[]" + nameMap[refName]
						}
					} else {
						goType = "[]string"
					}
				} else if typ, ok := prop["type"].(string); ok {
					if typ == "array" {
						goType = "[]string"
					} else if typ == "object" {
						if subProps, ok := prop["properties"].(map[string]interface{}); ok {
							nestedName := simpleName + capitalize(propName)
							nestedDef := fmt.Sprintf("type %s {", nestedName)
							var nestedFields []string
							for subName, subIf := range subProps {
								subProp, ok := subIf.(map[string]interface{})
								if !ok {
									continue
								}
								subType := "string"
								if subRef, ok := subProp["$ref"].(string); ok {
									subRefName := lastPartOfRef(subRef)
									subType = nameMap[subRefName]
								} else if subTyp, ok := subProp["type"].(string); ok {
									subType = swaggerTypeToGoZeroType(subTyp, getFormat(subProp))
								}
								tags := fmt.Sprintf("`json:\"%s\"`", subName)
								nestedFields = append(nestedFields, fmt.Sprintf("    %s %s %s", capitalize(subName), subType, tags))
							}
							sort.Strings(nestedFields)
							nestedDef += "\n" + strings.Join(nestedFields, "\n") + "\n}"
							nestedLines = append(nestedLines, nestedDef, "")
							goType = nestedName
						} else {
							goType = "map[string]string"
						}
					} else {
						goType = swaggerTypeToGoZeroType(typ, getFormat(prop))
					}
				}
				tags := fmt.Sprintf("`json:\"%s\"`", propName)
				if required, ok := schema["required"].([]interface{}); ok {
					for _, req := range required {
						if reqStr, ok := req.(string); ok && reqStr == propName {
							tags = fmt.Sprintf("`json:\"%s\" validate:\"required\"`", propName)
							break
						}
					}
				}
				fmt.Printf("++ %s %s %s\n", capitalize(propName), goType, tags)
				lines = append(lines, fmt.Sprintf("    %s %s %s", capitalize(propName), goType, tags))
			}
		}
		lines = append(lines, "}")
		allLines = append(allLines, strings.Join(lines, "\n"))
		allLines = append(allLines, "")
	}

	result := strings.Join(nestedLines, "\n")
	if result != "" && len(allLines) > 0 {
		result += "\n"
	}
	result += strings.Join(allLines, "\n")
	return result, nameMap, nil
}

func lastPartOfRef(ref string) string {
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

func getFormat(prop map[string]interface{}) string {
	if f, ok := prop["format"].(string); ok {
		return f
	}
	return ""
}

// --------------------------------------------------------------------
// Service statement generation
// --------------------------------------------------------------------

func generateServiceOp(path string, pathItemIf interface{}) (string, map[string]interface{}, error) {
	pathItem, ok := pathItemIf.(map[string]interface{})
	if !ok {
		return "", nil, fmt.Errorf("invalid path item")
	}
	for method, opIf := range pathItem {
		// method is like "get", "post", etc.
		if !isHTTPMethod(method) {
			continue
		}
		op, ok := opIf.(map[string]interface{})
		if !ok {
			continue
		}

		// Determine service name from path (same logic as groupPathsByService)
		normalized := strings.TrimPrefix(path, "/")
		components := strings.Split(normalized, "/")
		var serviceName string
		if len(components) < 2 {
			serviceName = "default"
		} else {
			serviceIdx := len(components) - 2
			if serviceIdx >= 0 && components[serviceIdx] != "" && !strings.HasPrefix(components[serviceIdx], "{") && !strings.HasPrefix(components[serviceIdx], ":") {
				serviceName = components[serviceIdx]
				serviceName = sanitizeIdentifier(strings.ToLower(serviceName))
			} else {
				serviceName = "default"
			}
		}

		opInfo := map[string]interface{}{
			"method":    method,
			"path":      path,
			"operation": op,
		}
		return serviceName, opInfo, nil
	}
	return "default", nil, fmt.Errorf("no valid operations found in paths")
}
func generateServiceStatements(paths map[string]interface{}, schemas map[string]interface{}, allDepends map[string]APIDependency) (string, error) {
	if len(paths) == 0 {
		return "", nil
	}
	serverLines := []string{}
	sortedPaths := make([]string, 0, len(paths))
	for path := range paths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	for _, path := range sortedPaths {
		opInfo := paths[path]
		serviceName, opInfoMeta, err := generateServiceOp(path, opInfo)
		if err != nil {
			continue
		}
		method := opInfoMeta["method"].(string)
		path = opInfoMeta["path"].(string)
		op := opInfoMeta["operation"].(map[string]interface{})

		if len(serverLines) == 0 {
			groupPrefix := getGroupPathFromPath(path)
			groupName := strings.TrimLeft(groupPrefix, "/")
			if groupName == "" {
				groupName = "default"
			}
			serviceLine := []string{
				"@server(",
				fmt.Sprintf("    prefix: %s", groupPrefix),
				fmt.Sprintf("    group: %s", groupName),
				")",
				fmt.Sprintf("service %s {", strings.ToLower(serviceName)),
			}
			serverLines = append(serverLines, serviceLine...)

		}

		handlerName := generateHandlerName(method, path, op)

		var docLines []string
		if desc, ok := op["description"].(string); ok && desc != "" {
			docLines = append(docLines, fmt.Sprintf("    @doc \"%s\"", escapeString(desc)))
		} else if summary, ok := op["summary"].(string); ok && summary != "" {
			docLines = append(docLines, fmt.Sprintf("    @doc \"%s\"", escapeString(summary)))
		}
		docLines = append(docLines, fmt.Sprintf("    @handler %s", handlerName))

		goZeroPath := convertPathParams(path)
		reqType, respType := determineRequestResponseTypes(op, handlerName, allDepends)

		route := fmt.Sprintf("    %s %s", method, goZeroPath)
		if reqType != "" {
			route += fmt.Sprintf(" (%s)", reqType)
		}
		if respType != "" {
			if reqType == "" {
				route += " returns"
			} else {
				route += " returns"
			}
			route += fmt.Sprintf(" (%s)", respType)
		}
		docLines = append(docLines, route, "")
		serverLines = append(serverLines, docLines...)
	}
	serverLines = append(serverLines, "}")
	serverLines = append(serverLines, "")
	return strings.Join(serverLines, "\n"), nil
}

func isHTTPMethod(m string) bool {
	switch m {
	case "get", "post", "put", "delete", "patch", "head", "options":
		return true
	}
	return false
}

func generateHandlerName(method, path string, op map[string]interface{}) string {
	if opID, ok := op["operationId"].(string); ok && opID != "" {
		return opID
	}
	processedPath := strings.TrimPrefix(path, "/")
	re := regexp.MustCompile(`\{([^}]+)\}`)
	processedPath = re.ReplaceAllStringFunc(processedPath, func(match string) string {
		paramName := match[1 : len(match)-1]
		if goKeywords[strings.ToLower(paramName)] {
			return paramName + "Param"
		}
		return paramName
	})
	parts := strings.Split(processedPath, "/")
	var camel string
	for _, p := range parts {
		if p != "" {
			camel += capitalize(p)
		}
	}
	return capitalize(method) + camel
}

func convertPathParams(path string) string {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	return re.ReplaceAllStringFunc(path, func(match string) string {
		paramName := match[1 : len(match)-1]
		if goKeywords[strings.ToLower(paramName)] {
			return ":" + paramName + "Param"
		}
		return ":" + paramName
	})
}

func determineRequestResponseTypes(op map[string]interface{}, handlerName string, allDepends map[string]APIDependency) (reqType, respType string) {
	// request
	if reqBody, ok := op["requestBody"].(map[string]interface{}); ok {
		if content, ok := reqBody["content"].(map[string]interface{}); ok {
			if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
				if schema, ok := jsonContent["schema"].(map[string]interface{}); ok {
					if ref, ok := schema["$ref"].(string); ok {
						reqType = allDepends[lastPartOfRef(ref)].nameMap[lastPartOfRef(ref)]
					} else if _, ok := schema["type"].(string); ok {
						reqType = handlerName + "Req"
					}
				}
			}
		}
	}
	if params, ok := op["parameters"].([]interface{}); ok {
		for _, p := range params {
			param, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if in, ok := param["in"].(string); ok && in == "body" {
				if schema, ok := param["schema"].(map[string]interface{}); ok {
					if ref, ok := schema["$ref"].(string); ok {
						reqType = allDepends[lastPartOfRef(ref)].nameMap[lastPartOfRef(ref)]
					} else if _, ok := schema["type"].(string); ok {
						reqType = handlerName + "Req"
					}
				}
			}
		}
	}

	// response
	if responses, ok := op["responses"].(map[string]interface{}); ok {
		for status, respIf := range responses {
			if strings.HasPrefix(status, "2") {
				resp, ok := respIf.(map[string]interface{})
				if !ok {
					continue
				}
				if content, ok := resp["content"].(map[string]interface{}); ok {
					if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
						if schema, ok := jsonContent["schema"].(map[string]interface{}); ok {
							if ref, ok := schema["$ref"].(string); ok {
								respType = allDepends[lastPartOfRef(ref)].nameMap[lastPartOfRef(ref)]
							} else if _, ok := schema["type"].(string); ok {
								respType = handlerName + "Resp"
							}
						}
					}
				}
				if schema, ok := resp["schema"].(map[string]interface{}); ok {
					if ref, ok := schema["$ref"].(string); ok {
						respType = allDepends[lastPartOfRef(ref)].nameMap[lastPartOfRef(ref)]
					} else if _, ok := schema["type"].(string); ok {
						respType = handlerName + "Resp"
					}
				}
				break
			}
		}
	}
	return
}

func escapeString(s string) string {
	return strings.ReplaceAll(s, "\"", "\\\"")
}

// --------------------------------------------------------------------
// Main API content generation
// --------------------------------------------------------------------
type APIDependency struct {
	usedSchemas map[string]interface{}
	visited     map[string]bool
	nameMap     map[string]string
}

func generateAPIContent(swagger map[string]interface{}, paths map[string]interface{}, schemas map[string]interface{}, refNameStat map[string]int) (string, error) {
	parsed := parseSwagger(swagger)
	if paths == nil {
		paths = parsed.Paths
	}
	if schemas == nil {
		schemas = parsed.Schemas
	}
	apiRefNameStat := make(map[string]int)
	allDepends := make(map[string]APIDependency)
	var collect func(string)
	collect = func(refName string) {
		shortRefName := lastPartOfRef(refName)
		shortRefNameParts := strings.Split(shortRefName, ".")
		shortRefName = shortRefNameParts[len(shortRefNameParts)-1]
		if v, ok := apiRefNameStat[shortRefName]; ok {
			apiRefNameStat[shortRefName] = v + 1
		} else {
			apiRefNameStat[shortRefName] = 1
		}
		v, ok := allDepends[refName]
		if ok {
			collectDependentSchemas(refName, schemas, v.usedSchemas, v.visited)
			return
		}
		usedSchemas := make(map[string]interface{})
		visited := make(map[string]bool)
		collectDependentSchemas(refName, schemas, usedSchemas, visited)
		allDepends[refName] = APIDependency{
			usedSchemas: usedSchemas,
			visited:     visited,
		}
	}

	// scan paths for references
	for _, pathItemIf := range paths {
		pathItem, ok := pathItemIf.(map[string]interface{})
		if !ok {
			continue
		}
		for method, opIf := range pathItem {
			if !isHTTPMethod(method) {
				continue
			}
			op, ok := opIf.(map[string]interface{})
			if !ok {
				continue
			}
			if reqBody, ok := op["requestBody"].(map[string]interface{}); ok {
				if content, ok := reqBody["content"].(map[string]interface{}); ok {
					if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
						if schema, ok := jsonContent["schema"].(map[string]interface{}); ok {
							if ref, ok := schema["$ref"].(string); ok {
								collect(lastPartOfRef(ref))
							}
						}
					}
				}
			}
			if params, ok := op["parameters"].([]interface{}); ok {
				for _, p := range params {
					param, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					if in, ok := param["in"].(string); ok && in == "body" {
						if schema, ok := param["schema"].(map[string]interface{}); ok {
							if ref, ok := schema["$ref"].(string); ok {
								collect(lastPartOfRef(ref))
							}
						}
					}
				}
			}
			if responses, ok := op["responses"].(map[string]interface{}); ok {
				for status, respIf := range responses {
					if strings.HasPrefix(status, "2") {
						resp, ok := respIf.(map[string]interface{})
						if !ok {
							continue
						}
						if content, ok := resp["content"].(map[string]interface{}); ok {
							if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
								if schema, ok := jsonContent["schema"].(map[string]interface{}); ok {
									if ref, ok := schema["$ref"].(string); ok {
										collect(lastPartOfRef(ref))
									}
								}
							}
						}
						if schema, ok := resp["schema"].(map[string]interface{}); ok {
							if ref, ok := schema["$ref"].(string); ok {
								collect(lastPartOfRef(ref))
							}
						}
					}
				}
			}
		}
	}

	var allTypeDecls []string
	var depNames []string
	for depName := range allDepends {
		depNames = append(depNames, depName)
	}
	sort.Strings(depNames)
	dumpTypes := make(map[string]bool)
	for _, depName := range depNames {
		dep := allDepends[depName]
		allTypeDecls = append(allTypeDecls, "// Types for "+depName)
		typeDecl, nameMap, err := generateTypeDeclarations(dep.usedSchemas, refNameStat, dumpTypes)
		if err != nil {
			return "", err
		}
		allTypeDecls = append(allTypeDecls, typeDecl)
		newdept := allDepends[depName]
		newdept.nameMap = nameMap
		allDepends[depName] = newdept
	}
	serviceStmt, err := generateServiceStatements(paths, schemas, allDepends)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.WriteString("syntax = \"v1\"\n\n")

	builder.WriteString("info(\n")
	if title, ok := parsed.Info["title"].(string); ok {
		builder.WriteString(fmt.Sprintf("    title: \"%s\"\n", escapeString(title)))
	}
	if version, ok := parsed.Info["version"].(string); ok {
		builder.WriteString(fmt.Sprintf("    version: \"%s\"\n", escapeString(version)))
	}
	if desc, ok := parsed.Info["description"].(string); ok {
		builder.WriteString(fmt.Sprintf("    description: \"%s\"\n", escapeString(desc)))
	}
	builder.WriteString(")\n\n")

	builder.WriteString(strings.Join(allTypeDecls, "\n"))
	builder.WriteString("\n")
	builder.WriteString(serviceStmt)

	return builder.String(), nil
}

func collectDependentSchemas(schemaName string, allSchemas map[string]interface{}, used map[string]interface{}, visited map[string]bool) {
	if visited[schemaName] {
		return
	}
	visited[schemaName] = true
	schemaIf, ok := allSchemas[schemaName]
	if !ok {
		return
	}
	schema, ok := schemaIf.(map[string]interface{})
	if !ok {
		return
	}
	used[schemaName] = schema

	if props, ok := schema["properties"].(map[string]interface{}); ok {
		for _, propIf := range props {
			prop, ok := propIf.(map[string]interface{})
			if !ok {
				continue
			}
			if ref, ok := prop["$ref"].(string); ok {
				collectDependentSchemas(lastPartOfRef(ref), allSchemas, used, visited)
			}
			if items, ok := prop["items"].(map[string]interface{}); ok {
				if itemRef, ok := items["$ref"].(string); ok {
					collectDependentSchemas(lastPartOfRef(itemRef), allSchemas, used, visited)
				}
			}
			if allOf, ok := prop["allOf"].([]interface{}); ok {
				for _, item := range allOf {
					if sub, ok := item.(map[string]interface{}); ok {
						if ref, ok := sub["$ref"].(string); ok {
							collectDependentSchemas(lastPartOfRef(ref), allSchemas, used, visited)
						}
					}
				}
			}
			if anyOf, ok := prop["anyOf"].([]interface{}); ok {
				for _, item := range anyOf {
					if sub, ok := item.(map[string]interface{}); ok {
						if ref, ok := sub["$ref"].(string); ok {
							collectDependentSchemas(lastPartOfRef(ref), allSchemas, used, visited)
						}
					}
				}
			}
			if oneOf, ok := prop["oneOf"].([]interface{}); ok {
				for _, item := range oneOf {
					if sub, ok := item.(map[string]interface{}); ok {
						if ref, ok := sub["$ref"].(string); ok {
							collectDependentSchemas(lastPartOfRef(ref), allSchemas, used, visited)
						}
					}
				}
			}
		}
	}
}

func statRefNames(schemas map[string]interface{}) map[string]int {
	refNameStat := make(map[string]int)
	for schemaKey := range schemas {
		parts := strings.Split(schemaKey, ".")
		base := parts[len(parts)-1]
		if v, ok := refNameStat[base]; ok {
			refNameStat[base] = v + 1
		} else {
			refNameStat[base] = 1
		}
	}
	for k, v := range refNameStat {
		if v <= 1 {
			continue
		}
		fmt.Printf("ref name:%s count:%d\n", k, v)
	}
	return refNameStat
}

// --------------------------------------------------------------------
// Grouped file generation
// --------------------------------------------------------------------

func generateGroupedFiles(swagger map[string]interface{}, outputDir string) error {
	parsed := parseSwagger(swagger)
	groups := groupPathsByService(parsed.Paths)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	refNameStat := statRefNames(parsed.Schemas)
	for groupPath, groupPathData := range groups {
		parts := strings.Split(groupPath, "/")
		servicePath := parts[:len(parts)-1]
		serviceName := parts[len(parts)-1]
		fullDir := filepath.Join(outputDir, strings.Join(servicePath, "/"))
		if err := os.MkdirAll(fullDir, 0755); err != nil {
			return err
		}

		serviceName = sanitizeIdentifier(strings.ToLower(serviceName))
		filePath := filepath.Join(fullDir, serviceName+".api")
		content, err := generateAPIContent(swagger, groupPathData, parsed.Schemas, refNameStat)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
			return err
		}
		fmt.Printf("Generated: %s\n", filePath)

	}
	return nil
}
