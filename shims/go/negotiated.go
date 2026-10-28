package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/dnsid-ai/dnsid-go/httpsig"
)

type fixtureResponse struct {
	Status     int
	Headers    map[string]string
	BodyBase64 *string
}

type fixtureComponent struct {
	Name   string
	Params map[string]any
}

func negotiatedMissing() map[string]any {
	return map[string]any{"ok": false, "error": "CapabilityMissing", "capability": "negotiated_response_signatures", "message": "SDK has no negotiated response APIs"}
}

func conformanceError(err error) map[string]any {
	return map[string]any{"ok": false, "error": "ConformanceError", "message": err.Error()}
}

func fixtureHTTPRequest(fixture httpFixtureRequest) (*http.Request, error) {
	var body io.Reader
	if fixture.BodyBase64 != nil {
		raw, err := base64.StdEncoding.DecodeString(*fixture.BodyBase64)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(fixture.Method, fixture.URL, body)
	if err != nil {
		return nil, err
	}
	for name, value := range fixture.Headers {
		req.Header.Set(name, value)
	}
	return req, nil
}

func fixtureHTTPResponse(fixture fixtureResponse, req *http.Request) (*http.Response, error) {
	res := &http.Response{StatusCode: fixture.Status, Header: http.Header{}, Request: req, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	for name, value := range fixture.Headers {
		res.Header.Set(name, value)
	}
	if fixture.BodyBase64 != nil {
		raw, err := base64.StdEncoding.DecodeString(*fixture.BodyBase64)
		if err != nil {
			return nil, err
		}
		res.Body = io.NopCloser(bytes.NewReader(raw))
	}
	return res, nil
}

// shortcut: reflection keeps the shim building against SDKs without negotiated
// responses; call the APIs directly once every tested SDK baseline ships them.
func handleNegotiated(req request) map[string]any {
	key, err := newFixtureKeyProvider(req.Key)
	if err != nil {
		return errJSON(err)
	}
	profile := httpsig.New(nil, req.Domain, key, httpsig.Config{})
	method := reflect.ValueOf(profile).MethodByName("SignRequestedHTTPResponse")
	field, hasOption := reflect.TypeOf(httpsig.SigningOptions{}).FieldByName("ResponseSignature")
	if !method.IsValid() || !hasOption {
		return negotiatedMissing()
	}
	switch req.Op {
	case "negotiated_response_base":
		origin, err := fixtureHTTPRequest(req.Request)
		if err != nil {
			return errJSON(err)
		}
		res, err := fixtureHTTPResponse(req.Response, origin)
		if err != nil {
			return errJSON(err)
		}
		inputs, err := httpsig.ParseSignatureInput(req.SignatureInput)
		if err != nil {
			return conformanceError(err)
		}
		params, ok := inputs[req.Label]
		if !ok {
			return conformanceError(fmt.Errorf("signature label %q not found", req.Label))
		}
		base, err := httpsig.BuildSignatureInput(res, params)
		if err != nil {
			return conformanceError(err)
		}
		return map[string]any{"ok": true, "value": base}
	case "negotiated_response_prepare":
		origin, err := fixtureHTTPRequest(req.Request)
		if err != nil {
			return errJSON(err)
		}
		policy := reflect.New(field.Type.Elem())
		policy.Elem().FieldByName("ExpectedDomain").SetString(req.ExpectedDomain)
		components := make([]httpsig.ComponentIdentifier, 0, len(req.AdditionalComponents))
		for _, component := range req.AdditionalComponents {
			components = append(components, httpsig.ComponentIdentifier{Name: component.Name, Params: component.Params})
		}
		policy.Elem().FieldByName("AdditionalComponents").Set(reflect.ValueOf(components))
		opts := httpsig.SigningOptions{Label: req.Label}
		reflect.ValueOf(&opts).Elem().FieldByIndex(field.Index).Set(policy)
		signed, err := profile.CreateSignedHTTPRequest(origin, opts)
		if err != nil {
			return conformanceError(err)
		}
		return map[string]any{"ok": true, "headers": wbaHeaders(signed.Header)}
	case "negotiated_response_sign":
		origin, err := fixtureHTTPRequest(req.Request)
		if err != nil {
			return errJSON(err)
		}
		res, err := fixtureHTTPResponse(req.Response, origin)
		if err != nil {
			return errJSON(err)
		}
		out := method.Call([]reflect.Value{reflect.ValueOf(origin), reflect.ValueOf(res)})
		if err, _ := out[1].Interface().(error); err != nil {
			return conformanceError(err)
		}
		signed := out[0].Interface().(*http.Response)
		var body []byte
		if signed.Body != nil {
			if body, err = io.ReadAll(signed.Body); err != nil {
				return errJSON(err)
			}
		}
		headers := map[string]string{}
		for name, values := range signed.Header {
			headers[strings.ToLower(name)] = strings.Join(values, ", ")
		}
		return map[string]any{"ok": true, "response": map[string]any{
			"status": signed.StatusCode, "headers": headers, "bodyBase64": base64.StdEncoding.EncodeToString(body),
		}}
	}
	return map[string]any{"ok": false, "error": "ShimError", "message": "unknown negotiated op"}
}
