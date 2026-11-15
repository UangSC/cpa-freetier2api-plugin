package codeartsweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"freetier2api-plugin/internal/core"
)

const (
	VendorID           = "codeartsweb"
	webOrigin          = "https://devcloud.cn-north-4.huaweicloud.com"
	maxCredentialBytes = 256 << 10
)

// Credential 保存原站浏览器会话；读取与响应 Cookie 轮换使用同一把锁。
type Credential struct {
	mu                                    sync.RWMutex
	Cookie, Cftk, UserID, UserName, Label string
	Headers                               map[string]string
	Raw                                   map[string]any
}

type credentialSnapshot struct {
	Cookie, Cftk, UserID, UserName, Label string
	Headers                               map[string]string
}

var browserHeaderNames = map[string]bool{
	"user-agent": true, "accept-language": true,
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true,
}

func credentialText(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func ParseCredential(data []byte) (*Credential, error) {
	if len(data) == 0 || len(data) > maxCredentialBytes {
		return nil, fmt.Errorf("CodeArts 网页凭证长度无效")
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil || raw == nil {
		return nil, fmt.Errorf("CodeArts 网页凭证必须是 JSON 对象")
	}
	if declared := credentialText(raw, "vendor"); declared != "" && declared != VendorID {
		return nil, fmt.Errorf("凭证不属于 CodeArts 网页通道")
	}
	for _, key := range []string{"type", "provider"} {
		if declared := credentialText(raw, key); declared != "" && declared != core.ProviderKey {
			return nil, fmt.Errorf("CodeArts 网页凭证的 type/provider 必须为 freetier")
		}
	}
	for _, key := range []string{"origin", "base_url", "web_origin"} {
		if origin := credentialText(raw, key); origin != "" && origin != webOrigin {
			return nil, fmt.Errorf("CodeArts 网页凭证只能用于华为云原站")
		}
	}
	headers := make(map[string]string)
	for _, key := range []string{"headers", "request_headers"} {
		if input, ok := raw[key].(map[string]any); ok {
			for name, item := range input {
				value, okValue := item.(string)
				if !okValue || !validHeaderValue(value) || !validHeaderName(name) {
					return nil, fmt.Errorf("CodeArts 网页请求头格式无效")
				}
				headers[strings.ToLower(name)] = strings.TrimSpace(value)
			}
		}
	}
	cookie := credentialText(raw, "cookie", "cookie_header")
	cftk := credentialText(raw, "cftk")
	if cookie != "" && headers["cookie"] != "" && cookie != headers["cookie"] {
		return nil, fmt.Errorf("凭证字段与请求头中的 Cookie 存在矛盾")
	}
	if cftk != "" && headers["cftk"] != "" && cftk != headers["cftk"] {
		return nil, fmt.Errorf("凭证字段与请求头中的 cftk 存在矛盾")
	}
	if cookie == "" {
		cookie = headers["cookie"]
	}
	if cftk == "" {
		cftk = headers["cftk"]
	}
	curl := credentialText(raw, "curl")
	apiKey := credentialText(raw, "api_key")
	if curl == "" && strings.HasPrefix(apiKey, "curl ") {
		curl = apiKey
	}
	if curl != "" {
		captured, err := parseCurlHeaders(curl)
		if err != nil {
			return nil, err
		}
		if cookie != "" && captured["cookie"] != "" && cookie != captured["cookie"] {
			return nil, fmt.Errorf("凭证中的 Cookie 快照存在矛盾")
		}
		if cftk != "" && captured["cftk"] != "" && cftk != captured["cftk"] {
			return nil, fmt.Errorf("凭证中的 cftk 快照存在矛盾")
		}
		if cookie == "" {
			cookie = captured["cookie"]
		}
		if cftk == "" {
			cftk = captured["cftk"]
		}
		for name, value := range captured {
			headers[name] = value
		}
	}
	if cookie == "" && apiKey != "" {
		cookie = apiKey
	}
	if !validCookieHeader(cookie) {
		return nil, fmt.Errorf("CodeArts 网页凭证需要完整的会话 Cookie，不能使用 AK/SK")
	}
	cookieCftk := findCookieCftk(cookie)
	if cftk == "" {
		cftk = cookieCftk
	}
	if cftk == "" || !validHeaderValue(cftk) || (cookieCftk != "" && cookieCftk != cftk) {
		return nil, fmt.Errorf("CodeArts 网页凭证缺少 cftk，或与 Cookie 不一致")
	}
	filtered := make(map[string]string)
	for name, value := range headers {
		if browserHeaderNames[name] {
			filtered[name] = value
		}
	}
	if agent := credentialText(raw, "user_agent", "userAgent"); agent != "" {
		if !validHeaderValue(agent) {
			return nil, fmt.Errorf("浏览器 User-Agent 格式无效")
		}
		filtered["user-agent"] = agent
	}
	label := credentialText(raw, "label")
	name := credentialText(raw, "user_name", "userName")
	if label == "" {
		label = name
	}
	if label == "" {
		label = "CodeArts 网页"
	}
	return &Credential{Cookie: cookie, Cftk: cftk, UserID: credentialText(raw, "user_id", "userId"),
		UserName: name, Label: label, Headers: filtered, Raw: raw}, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return false
	}
	return true
}

func validHeaderValue(value string) bool {
	for _, char := range value {
		if char == '\r' || char == '\n' || char == 0 || char == 127 || (char < 32 && char != '\t') {
			return false
		}
	}
	return true
}

func validCookieHeader(value string) bool {
	if strings.TrimSpace(value) == "" || !validHeaderValue(value) {
		return false
	}
	request := &http.Request{Header: http.Header{"Cookie": {value}}}
	parsed := request.Cookies()
	count := 0
	for _, segment := range strings.Split(value, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		name, _, ok := strings.Cut(segment, "=")
		if !ok || !validHeaderName(strings.TrimSpace(name)) {
			return false
		}
		count++
	}
	return count > 0 && len(parsed) == count
}

func findCookieCftk(cookie string) string {
	request := &http.Request{Header: http.Header{"Cookie": {cookie}}}
	for _, value := range request.Cookies() {
		if strings.HasSuffix(strings.ToLower(value.Name), "cftk") {
			decoded, err := url.PathUnescape(value.Value)
			if err == nil {
				return decoded
			}
		}
	}
	return ""
}

func (credential *Credential) snapshot() credentialSnapshot {
	if credential == nil {
		return credentialSnapshot{}
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	headers := make(map[string]string, len(credential.Headers))
	for name, value := range credential.Headers {
		headers[name] = value
	}
	return credentialSnapshot{Cookie: credential.Cookie, Cftk: credential.Cftk, UserID: credential.UserID,
		UserName: credential.UserName, Label: credential.Label, Headers: headers}
}

func (credential *Credential) setIdentity(id, name string) error {
	if id == "" {
		return fmt.Errorf("CodeArts 网页身份缺少 userId")
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	if credential.UserID != "" && credential.UserID != id {
		return fmt.Errorf("CodeArts 网页凭证的账号身份不一致")
	}
	credential.UserID, credential.UserName = id, name
	if credential.Label == "" || credential.Label == "CodeArts 网页" {
		credential.Label = core.FirstNonEmpty(name, id)
	}
	return nil
}

func (credential *Credential) absorbCookies(values []*http.Cookie) {
	if len(values) == 0 {
		return
	}
	credential.mu.Lock()
	defer credential.mu.Unlock()
	request := &http.Request{Header: http.Header{"Cookie": {credential.Cookie}}}
	current := request.Cookies()
	cftkRemoved := false
	for _, updated := range values {
		if updated.Domain != "" && updated.Domain != "devcloud.cn-north-4.huaweicloud.com" && updated.Domain != ".devcloud.cn-north-4.huaweicloud.com" && updated.Domain != ".huaweicloud.com" && updated.Domain != "huaweicloud.com" {
			continue
		}
		if updated.Valid() != nil {
			continue
		}
		found := -1
		for index, value := range current {
			if value.Name == updated.Name {
				found = index
				break
			}
		}
		if updated.MaxAge < 0 || !updated.Expires.IsZero() && updated.Expires.Before(time.Now()) {
			if strings.HasSuffix(strings.ToLower(updated.Name), "cftk") {
				cftkRemoved = true
			}
			if found >= 0 {
				current = append(current[:found], current[found+1:]...)
			}
			continue
		}
		copy := *updated
		if found >= 0 {
			current[found] = &copy
		} else {
			current = append(current, &copy)
		}
	}
	parts := make([]string, 0, len(current))
	for _, value := range current {
		parts = append(parts, value.Name+"="+value.Value)
	}
	credential.Cookie = strings.Join(parts, "; ")
	if token := findCookieCftk(credential.Cookie); token != "" {
		credential.Cftk = token
	} else if cftkRemoved {
		credential.Cftk = ""
	}
}

func (credential *Credential) StorageJSON() ([]byte, error) {
	if credential == nil {
		return nil, fmt.Errorf("CodeArts 网页凭证为空")
	}
	credential.mu.RLock()
	defer credential.mu.RUnlock()
	encoded, err := json.Marshal(credential.Raw)
	if err != nil {
		return nil, fmt.Errorf("无法保存 CodeArts 网页凭证")
	}
	raw := make(map[string]any)
	if len(encoded) > 0 {
		_ = json.Unmarshal(encoded, &raw)
	}
	if raw == nil {
		raw = make(map[string]any)
	}
	for _, key := range []string{"curl", "api_key", "request_headers", "cookie_header", "userAgent", "user_agent"} {
		delete(raw, key)
	}
	raw["type"], raw["vendor"] = core.ProviderKey, VendorID
	raw["cookie"], raw["cftk"] = credential.Cookie, credential.Cftk
	raw["user_id"], raw["user_name"], raw["label"] = credential.UserID, credential.UserName, credential.Label
	raw["headers"] = credential.Headers
	return json.Marshal(raw)
}

// parseCurlHeaders 只解释浏览器导出的参数，不调用 shell 或执行任意命令。
func parseCurlHeaders(value string) (map[string]string, error) {
	parts, err := splitCurlWords(value)
	if err != nil || len(parts) == 0 || (parts[0] != "curl" && parts[0] != "curl.exe") {
		return nil, fmt.Errorf("请提供浏览器导出的 cURL (bash)")
	}
	headers := make(map[string]string)
	destination := ""
	for index := 1; index < len(parts); index++ {
		argument := parts[index]
		switch argument {
		case "-H", "--header", "-b", "--cookie", "--url", "-X", "--request", "-d", "--data", "--data-raw", "--data-binary":
			index++
			if index >= len(parts) {
				return nil, fmt.Errorf("cURL 参数缺少值")
			}
			item := parts[index]
			switch argument {
			case "--url":
				destination = item
			case "-b", "--cookie":
				headers["cookie"] = item
			case "-H", "--header":
				name, content, ok := strings.Cut(item, ":")
				if !ok || !validHeaderName(name) || !validHeaderValue(content) {
					return nil, fmt.Errorf("cURL 请求头格式无效")
				}
				headers[strings.ToLower(name)] = strings.TrimSpace(content)
			}
		case "--compressed", "--location", "-L", "--globoff":
		default:
			if strings.HasPrefix(argument, "https://") && destination == "" {
				destination = argument
			} else {
				return nil, fmt.Errorf("cURL 包含不支持的参数，请复制为 cURL (bash)")
			}
		}
	}
	parsed, err := url.Parse(destination)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "devcloud.cn-north-4.huaweicloud.com" || parsed.User != nil || !strings.HasPrefix(parsed.Path, "/chat/") || parsed.Fragment != "" {
		return nil, fmt.Errorf("cURL 只能来自华为云原站的 /chat/ 请求")
	}
	return headers, nil
}

func splitCurlWords(value string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	escaped, active := false, false
	for _, char := range value {
		if escaped {
			if char != '\n' && char != '\r' {
				word.WriteRune(char)
				active = true
			}
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				word.WriteRune(char)
			}
			active = true
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			active = true
			continue
		}
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			if active {
				words = append(words, word.String())
				word.Reset()
				active = false
			}
			continue
		}
		word.WriteRune(char)
		active = true
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("cURL 引号或转义未闭合")
	}
	if active {
		words = append(words, word.String())
	}
	return words, nil
}
