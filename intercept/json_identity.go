package intercept

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// uniqueJSONObject rejects duplicate keys at every nesting level. Target APIs
// may use first-key or last-key semantics; neither interpretation is trusted for
// authorization/account limits when a request has more than one identity.
func uniqueJSONObject(raw string) (map[string]any, error) {
	d := json.NewDecoder(strings.NewReader(raw))
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 128 {
			return nil, fmt.Errorf("JSON 嵌套超过身份检查上限")
		}
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delim {
		case '{':
			object := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, e
				}
				name, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("无效 JSON 属性")
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("JSON 属性重复：%s", name)
				}
				value, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				object[name] = value
			}
			_, e = d.Token()
			return object, e
		case '[':
			values := []any{}
			for d.More() {
				value, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				values = append(values, value)
			}
			_, e = d.Token()
			return values, e
		default:
			return nil, fmt.Errorf("无效 JSON 分隔符")
		}
	}
	value, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fmt.Errorf("JSON 含多余内容")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON 不是对象")
	}
	return object, nil
}
