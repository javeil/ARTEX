package intercept

import (
	"fmt"
	"strings"
)

// HTTP clients may be called observable only after their whole argv is static
// and the options cannot create another transport or load an executable config.
// Consume option values before checking the next token: a POST body beginning
// with '-x' is data, not a proxy option.
func validateHTTPClientArgs(name string, args []string) error {
	_, err := httpClientDestinations(name, args)
	return err
}

// Return only network destinations; option payloads and local output paths are data.
func httpClientDestinations(name string, args []string) (destinations []string, err error) {
	dangerous := []string{"--proxy", "--noproxy", "--socks", "--config", "--connect-to", "--resolve", "--next", "--preproxy", "--doh-url", "--unix-socket", "--abstract-unix-socket", "--execute", "--no-proxy", "--use-askpass", "--follow-ftp", "--input-file", "--expand", "--variable", "--alt-svc"}
	values := map[string]bool{}
	for _, v := range strings.Fields("--request --method --data --data-raw --data-binary --data-urlencode --json --form --form-string --header --cookie --cookie-jar --user --user-agent --referer --output --output-document --dump-header --upload-file --url --url-query --range --max-time --connect-timeout --retry --retry-delay --retry-max-time --max-redirs --max-redirect --cacert --capath --cert --key --ciphers --post-data --post-file --body-data --body-file --timeout --tries --wait --waitretry --limit-rate --accept --reject --directory-prefix --cut-dirs --user-password --http-user --http-password --domains --exclude-domains --level") {
		values[v] = true
	}
	flags := map[string]bool{}
	for _, v := range strings.Fields("--silent --show-error --fail --fail-with-body --insecure --location --location-trusted --head --get --globoff --path-as-is --compressed --http1.0 --http1.1 --http2 --http2-prior-knowledge --ipv4 --ipv6 --basic --digest --anyauth --ntlm --negotiate --netrc --netrc-optional --no-buffer --include --verbose --version --help --disable --remote-name --remote-header-name --remote-time --parallel --parallel-immediate --progress-bar --no-progress-meter --continue --recursive --no-parent --page-requisites --convert-links --adjust-extension --timestamping --span-hosts --relative --force-html --no-config --no-check-certificate --quiet --server-response --spider --no-verbose --debug --background") {
		flags[v] = true
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return nil, fmt.Errorf("HTTP 客户端不允许终止参数解析后覆盖目标网关，请用 TargetHTTP")
		}
		if strings.HasPrefix(arg, "--") {
			option, value, hasValue := strings.Cut(arg, "=")
			for _, blocked := range dangerous {
				// curl/wget accept abbreviated long options; do not admit an abbreviation
				// of a forbidden transport/configuration option.
				if strings.HasPrefix(option, blocked) || strings.HasPrefix(blocked, option) {
					return nil, fmt.Errorf("HTTP 客户端参数不能覆盖网关或载入外部配置：%s", option)
				}
			}
			if !values[option] && !flags[option] {
				return nil, fmt.Errorf("不支持验证的 HTTP 客户端选项：%s，请使用 TargetHTTP", option)
			}
			if values[option] && !hasValue {
				i++
				if i >= len(args) {
					return nil, fmt.Errorf("HTTP 参数缺少值：%s", option)
				}
			}
			if option == "--url" {
				if !hasValue {
					value = args[i]
				}
				destinations = append(destinations, value)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			valueFlags := "AbcCdDeEFHmoQrTuwXYyz"
			boolFlags := "012346afgGIijJklLnNOpqRsSvVZ#"
			forbidden := "xK:U"
			if name == "wget" {
				valueFlags = "aABDoOPQUwWtTlRXI"
				boolFlags = "qvdrNncSpkKEmHLFbs"
				forbidden = "ei"
			}
			for j := 1; j < len(arg); j++ {
				if strings.ContainsRune(forbidden, rune(arg[j])) {
					return nil, fmt.Errorf("HTTP 短参数不能覆盖网关或载入配置：%s", arg)
				}
				if strings.ContainsRune(valueFlags, rune(arg[j])) {
					if j == len(arg)-1 {
						i++
						if i >= len(args) {
							return nil, fmt.Errorf("HTTP 参数缺少值：%s", arg)
						}
					}
					break
				}
				if !strings.ContainsRune(boolFlags, rune(arg[j])) {
					return nil, fmt.Errorf("不支持验证的 HTTP 短选项：%s", arg)
				}
			}
			continue
		}
		if strings.Contains(arg, "://") && !strings.HasPrefix(strings.ToLower(arg), "http://") && !strings.HasPrefix(strings.ToLower(arg), "https://") {
			return nil, fmt.Errorf("此任务网关仅支持 HTTP(S) 客户端目标")
		}
		destinations = append(destinations, arg)
	}
	return destinations, nil
}
