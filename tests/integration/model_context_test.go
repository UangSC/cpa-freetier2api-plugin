package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/app"
	"freetier2api-plugin/internal/vendors/qoder"
)

func TestQoderContextRegistrationAndBothExecutionModes(t *testing.T) {
	host := installFakeHost(t)
	setupTestPlugin(t)
	host.addAccount("qoder", "qodercn-test.json", `{"vendor":"qodercn","region":"cn","device_token":"dt-test","refresh_token":"drt-test"}`)
	type sentModel struct {
		Key   string `json:"key"`
		Limit int64  `json:"max_input_tokens"`
	}
	sent := make(chan sentModel, 8)
	host.setUpstream(func(method, url, body string) fakeUpstreamResponse {
		switch {
		case strings.Contains(url, "/api/v1/userinfo"):
			return fakeUpstreamResponse{Status: 200, Body: `{"id":"qoder-test","name":"test"}`}
		case strings.Contains(url, "/model/list"):
			return fakeUpstreamResponse{Status: 200, Body: `{"assistant":[{"key":"dfmodel","display_name":"DeepSeek-Flash","enable":true,"max_input_tokens":180000,"context_config":{"200K":{"is_default":true,"token_count":200000},"1M":{"token_count":1000000}}}]}`}
		case strings.Contains(url, "agent_chat_generation"):
			plain, errDecode := qoder.Decode(body)
			if errDecode != nil {
				return fakeUpstreamResponse{Status: 400, Body: "bad encoding"}
			}
			var request struct {
				Model sentModel `json:"model_config"`
			}
			if err := json.Unmarshal(plain, &request); err != nil {
				return fakeUpstreamResponse{Status: 400, Body: "bad request"}
			}
			sent <- request.Model
			envelope, _ := json.Marshal(map[string]any{"statusCodeValue": 200, "body": `{"choices":[{"delta":{"role":"assistant","content":"ok"}}]}`})
			return fakeUpstreamResponse{Status: 200, Body: "data: " + string(envelope) + "\n\ndata: [DONE]\n\n"}
		}
		return fakeUpstreamResponse{Status: 404, Body: `{}`}
	})
	registered := func(want int64) {
		t.Helper()
		var response pluginapi.ModelResponse
		if err := json.Unmarshal(callMethod(t, pluginabi.MethodModelForAuth, pluginapi.AuthModelRequest{AuthID: "qoder"}), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Models) != 1 || response.Models[0].ContextLength != want || response.Models[0].InputTokenLimit != want {
			t.Fatalf("registered models = %+v, want context %d", response.Models, want)
		}
	}
	execute := func(stream bool, want int64) {
		t.Helper()
		method := pluginabi.MethodExecutorExecute
		if stream {
			method = pluginabi.MethodExecutorExecuteStream
		}
		callMethod(t, method, app.ExecutorRPCRequest{
			ExecutorRequest: pluginapi.ExecutorRequest{
				AuthID: "qoder", Model: "my-qoder", Format: app.FormatChatCompletions, Stream: stream,
				Payload: []byte(`{"model":"my-qoder","messages":[{"role":"user","content":"hi"}],"context_length":99999999}`),
			},
			StreamID: "context-test",
		})
		select {
		case model := <-sent:
			if model.Key != "dfmodel" || model.Limit != want {
				t.Fatalf("upstream model config = %+v, want dfmodel / %d", model, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("upstream request was not sent")
		}
		testApp.WaitPluginStreams(3 * time.Second)
		if len(host.streamErrors()) > 0 {
			t.Fatalf("stream errors: %v", host.streamErrors())
		}
	}
	registered(1_000_000)
	testApp.Model().SetAlias("qodercn", "deepseek-flash", "my-qoder")
	execute(false, 1_000_000)
	response := managementCallWithBody(t, http.MethodPost, "/models/context", map[string]any{"model": "qodercn:deepseek-flash", "context_length": 400_000})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set context: %s", response.Body)
	}
	registered(400_000)
	console := managementCall(t, http.MethodGet, "/models")
	var view struct {
		Models []struct {
			ID                    string `json:"id"`
			ContextLength         int64  `json:"context_length"`
			UpstreamContextLength int64  `json:"upstream_context_length"`
			ContextOverride       int64  `json:"context_override"`
		} `json:"models"`
	}
	if err := json.Unmarshal(console.Body, &view); err != nil || len(view.Models) != 1 {
		t.Fatalf("invalid model console: %s (%v)", console.Body, err)
	}
	if model := view.Models[0]; model.ContextLength != 400_000 || model.UpstreamContextLength != 1_000_000 || model.ContextOverride != 400_000 {
		t.Fatalf("console lost upstream or effective context: %+v", model)
	}
	execute(false, 400_000)
	execute(true, 400_000)
	response = managementCallWithBody(t, http.MethodPost, "/models/context", map[string]any{"model": "qodercn:deepseek-flash", "context_length": 0})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("reset context: %s", response.Body)
	}
	registered(1_000_000)
	execute(true, 1_000_000)
}
