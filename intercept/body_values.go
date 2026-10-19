package intercept

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// Preserve repeated fields: frameworks differ on which occurrence wins. Files
// remain opaque payloads, rather than being mistaken for account form fields.
func bodyValues(o Operation) (url.Values, error) {
	values := url.Values{}
	if o.Body == "" {
		return values, nil
	}
	media, params, err := mime.ParseMediaType(o.ContentType)
	if o.ContentType != "" && err != nil {
		return nil, err
	}
	if media == "multipart/form-data" {
		if params["boundary"] == "" {
			return nil, fmt.Errorf("missing multipart boundary")
		}
		reader := multipart.NewReader(strings.NewReader(o.Body), params["boundary"])
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if part.FormName() == "" {
				return nil, fmt.Errorf("unnamed multipart field")
			}
			if part.FileName() != "" {
				part.Close()
				continue
			}
			b, err := io.ReadAll(io.LimitReader(part, (1<<20)+1))
			part.Close()
			if err != nil {
				return nil, err
			}
			if len(b) > 1<<20 {
				return nil, fmt.Errorf("multipart field exceeds inspection limit")
			}
			values.Add(part.FormName(), string(b))
		}
		return values, nil
	}
	if media == "application/json" || strings.HasPrefix(strings.TrimSpace(o.Body), "{") {
		obj, err := uniqueJSONObject(o.Body)
		if err != nil {
			return nil, err
		}
		for k, v := range obj {
			if s, ok := v.(string); ok {
				values.Add(k, s)
			}
		}
		return values, nil
	}
	if media == "" || media == "application/x-www-form-urlencoded" {
		return url.ParseQuery(o.Body)
	}
	return nil, fmt.Errorf("opaque request media type")
}
