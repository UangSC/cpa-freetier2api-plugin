package tokenplan

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func testRepeatedSchema() map[string]any {
	item := map[string]any{"type": "object", "additionalProperties": false, "required": []any{"query"},
		"properties":  map[string]any{"query": map[string]any{"type": "string", "minLength": json.Number("1"), "pattern": "^[a-z]+$"}},
		"description": strings.Repeat("Argument constraints remain identical. ", 12)}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []any{"left", "right"},
		"properties": map[string]any{"left": item, "right": item}, "examples": []any{item}}
}

func expandSchemaForTest(schema, root map[string]any) map[string]any {
	if reference, ok := schema["$ref"].(string); ok && strings.HasPrefix(reference, "#/$defs/") {
		target := root["$defs"].(map[string]any)[strings.TrimPrefix(reference, "#/$defs/")].(map[string]any)
		return expandSchemaForTest(target, root)
	}
	return schemaChildren(schema, func(child map[string]any) map[string]any { return expandSchemaForTest(child, root) })
}

func TestSchemaCompactionPreservesConstraintsAndExamples(t *testing.T) {
	original := testRepeatedSchema()
	before := schemaKey(original)
	optimized := compactSchema(original)
	if schemaKey(original) != before {
		t.Fatal("不能修改原始 Schema")
	}
	if len(schemaKey(optimized)) >= len(before) {
		t.Fatal("未减少重复结构")
	}
	expanded := expandSchemaForTest(optimized, optimized)
	delete(expanded, "$defs")
	if !reflect.DeepEqual(expanded, original) {
		t.Fatal("引用展开后的验证约束或示例发生了变化")
	}
	if !reflect.DeepEqual(optimized["examples"], original["examples"]) {
		t.Fatal("examples 是数据，不能替换成 Schema 引用")
	}
}

func TestSchemaCompactionLeavesScopedAndCollidingSchemasUntouched(t *testing.T) {
	for _, key := range []string{"$id", "$anchor", "$dynamicRef"} {
		original := testRepeatedSchema()
		original[key] = "local-scope"
		before := schemaKey(original)
		if schemaKey(compactSchema(original)) != before {
			t.Fatal("不能移动带引用作用域的 Schema")
		}
	}
	original := testRepeatedSchema()
	original["$defs"] = map[string]any{"freetier_schema_0": map[string]any{"type": "boolean"}}
	if schemaKey(compactSchema(original)) != schemaKey(original) {
		t.Fatal("新引用不得覆盖已有定义")
	}
}

func TestToolCompactionPreservesIdentityAndLargeNumbers(t *testing.T) {
	schema := testRepeatedSchema()
	schema["default"] = json.Number("9007199254740993")
	tools := []map[string]any{{"type": "function", "function": map[string]any{"name": "left_tool", "description": "左工具", "parameters": schema}},
		{"type": "function", "function": map[string]any{"name": "right_tool", "description": "右工具", "parameters": schema}}}
	raw, _ := json.Marshal(tools)
	optimized := compactTools(raw)
	if !strings.Contains(string(optimized), "9007199254740993") {
		t.Fatal("JSON 数字精度发生变化")
	}
	var result []map[string]any
	if json.Unmarshal(optimized, &result) != nil || len(result) != 2 {
		t.Fatal("工具清单发生变化")
	}
	for index, tool := range result {
		function := tool["function"].(map[string]any)
		original := tools[index]["function"].(map[string]any)
		if function["name"] != original["name"] || function["description"] != original["description"] {
			t.Fatal("工具身份或用途说明不能改变")
		}
	}
}
