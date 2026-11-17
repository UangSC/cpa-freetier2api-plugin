package hostbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
)

func TestWireProfilePassesThroughBothHostTransports(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "stream"}[stream], func(t *testing.T) {
			profile := pluginapi.HTTPWireProfile{DisableAutoCompression: true, HeaderProfile: []string{"Authorization", "id", "Accept"}}
			ctx := WithWireProfile(context.Background(), profile)
			profile.HeaderProfile[0] = "mutated"
			Configure(func(_, method string, payload any) (json.RawMessage, error) {
				if method == "host.http.stream_close" {
					return json.RawMessage(`{}`), nil
				}
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				var request rpcHostHTTPRequest
				if err := json.Unmarshal(raw, &request); err != nil {
					t.Fatal(err)
				}
				if request.WireProfile == nil || !request.WireProfile.DisableAutoCompression || request.WireProfile.HeaderProfile[0] != "Authorization" {
					t.Fatal("宿主桥丢失或污染请求头配置")
				}
				if stream {
					return json.RawMessage(`{"status_code":200,"stream_id":"test"}`), nil
				}
				return json.RawMessage(`{"StatusCode":200,"Body":""}`), nil
			})
			t.Cleanup(func() { Configure(nil) })
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := (&transport{ctx: context.Background(), stream: stream}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if !stream {
				_, _ = io.Copy(io.Discard, response.Body)
			}
			_ = response.Body.Close()
		})
	}
}
