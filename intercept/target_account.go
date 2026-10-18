package intercept

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func operationAccount(p db.TargetPolicy, o Operation) (string, error) {
	if o.Effect != "authenticate" {
		return "", nil
	}
	field := ""
	for _, r := range p.Operations {
		if r.Effect == "authenticate" && r.Target.Matches(o.Target) && r.AccountField != "" {
			for _, m := range r.Methods {
				if m == o.Method {
					field = r.AccountField
				}
			}
		}
	}
	fields := []string{"username", "user", "email", "login", "account"}
	if field != "" {
		fields = []string{field}
	}
	candidates := map[string]bool{}
	values := map[string][]string{}
	if u, e := url.Parse(o.Target.URL); e == nil {
		for k, v := range u.Query() {
			values[k] = append(values[k], v...)
		}
	}
	obj, jsonErr := uniqueJSONObject(o.Body)
	if strings.HasPrefix(strings.TrimSpace(o.Body), "{") && jsonErr != nil && (p.Budget.AccountAttempts > 0 || len(p.Accounts) > 0) {
		return "", fmt.Errorf("无法唯一解析登录账号：%w", jsonErr)
	}
	if jsonErr == nil {
		for _, key := range fields {
			var value any = obj
			for _, part := range strings.Split(key, ".") {
				m, ok := value.(map[string]any)
				if !ok {
					value = nil
					break
				}
				value = m[part]
			}
			if v, ok := value.(string); ok {
				values[key] = append(values[key], v)
			}
		}
	} else if q, e := url.ParseQuery(o.Body); e == nil {
		for k, v := range q {
			values[k] = append(values[k], v...)
		}
	}
	for _, key := range fields {
		for _, v := range values[key] {
			if v != "" {
				candidates[v] = true
			}
		}
	}
	if len(candidates) != 1 {
		if p.Budget.AccountAttempts > 0 || len(p.Accounts) > 0 {
			return "", fmt.Errorf("无法唯一确认实际登录账号，不能绕过账号范围/尝试预算")
		}
		return "", nil
	}
	var account string
	for v := range candidates {
		account = v
	}
	if len(p.Accounts) > 0 {
		allowed := false
		for _, v := range p.Accounts {
			allowed = allowed || v == account
		}
		if !allowed {
			return "", fmt.Errorf("账号不在本任务授权账号集合")
		}
	}
	// A conservative folded counter prevents case variants from resetting attempts.
	return strings.ToLower(strings.TrimSpace(account)), nil
}
