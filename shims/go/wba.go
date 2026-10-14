package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/dnsid-ai/dnsid-go/webbotauth"
)

type wbaConfig struct {
	SignatureAgent                      struct{ URI, Type string }
	SignatureTTL, DirectorySignatureTTL *int
	IncludeSignatureAgent               *bool
}

type wbaSigningOptions struct {
	AdditionalComponents []string
	SignatureAgent       *bool
	TTL                  *int
}

func wbaHeaders(header http.Header) map[string]string {
	values := map[string]string{}
	for name, fields := range header {
		values[strings.ToLower(name)] = strings.Join(fields, ", ")
	}
	return values
}

func handleWBA(req request) map[string]any {
	if req.Op == "wba_verify_request" {
		if _, present := reflect.TypeOf((*webbotauth.Profile)(nil)).MethodByName("VerifyWebBotAuthSignedRequest"); present {
			return map[string]any{"ok": false, "error": "NativeAdapterRequired", "message": "harness executes the native Go WBA test bridge"}
		}
		return map[string]any{"ok": false, "error": "CapabilityMissing", "capability": "wba_request_verification", "message": "SDK has signing/directory serving only"}
	}
	key, err := newFixtureKeyProvider(req.Key)
	if err != nil {
		return errJSON(err)
	}
	cfg := webbotauth.Config{
		DirectoryURL:          req.WebBotAuth.SignatureAgent.URI,
		SignatureAgentType:    req.WebBotAuth.SignatureAgent.Type,
		IncludeSignatureAgent: req.WebBotAuth.IncludeSignatureAgent,
	}
	if req.WebBotAuth.SignatureTTL != nil {
		cfg.SignatureTTL = time.Duration(*req.WebBotAuth.SignatureTTL) * time.Second
	}
	if req.WebBotAuth.DirectorySignatureTTL != nil {
		cfg.DirectorySignatureTTL = time.Duration(*req.WebBotAuth.DirectorySignatureTTL) * time.Second
	}
	profile := webbotauth.New(req.Domain, key, cfg)
	if req.ConfigMutation.IncludeSignatureAgent != nil && cfg.IncludeSignatureAgent != nil {
		*cfg.IncludeSignatureAgent = *req.ConfigMutation.IncludeSignatureAgent
	}
	if req.ConfigMutation.SignatureAgent.URI != "" {
		cfg.DirectoryURL = req.ConfigMutation.SignatureAgent.URI
	}
	message, err := http.NewRequest(req.Request.Method, req.Request.URL, nil)
	if err != nil {
		return errJSON(err)
	}
	for name, value := range req.Request.Headers {
		message.Header.Set(name, value)
	}
	if req.Request.BodyBase64 != nil {
		body, decodeErr := base64.StdEncoding.DecodeString(*req.Request.BodyBase64)
		if decodeErr != nil {
			return errJSON(decodeErr)
		}
		// Keep supplied empty content distinct from http.NoBody.
		message.Body = io.NopCloser(bytes.NewReader(body))
		message.ContentLength = int64(len(body))
	}
	var output map[string]any
	switch req.Operation {
	case "directory":
		response, serveErr := profile.ServeHttpMessageSignaturesDirectory(message)
		if serveErr != nil {
			return errJSON(serveErr)
		}
		body, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			return errJSON(readErr)
		}
		output = map[string]any{"status": response.StatusCode, "headers": wbaHeaders(response.Header), "bodyBase64": base64.StdEncoding.EncodeToString(body)}
	case "request":
		opts := webbotauth.SigningOptions{AdditionalComponents: req.Options.AdditionalComponents, SignatureAgent: req.Options.SignatureAgent}
		if req.Options.TTL != nil {
			opts.TTL = time.Duration(*req.Options.TTL) * time.Second
		}
		signed, signErr := profile.CreateWebBotAuthSignedRequest(message, opts)
		if signErr != nil {
			return errJSON(signErr)
		}
		var encoded any
		if req.Request.BodyBase64 != nil {
			body, readErr := io.ReadAll(signed.Body)
			if readErr != nil {
				return errJSON(readErr)
			}
			encoded = base64.StdEncoding.EncodeToString(body)
		}
		output = map[string]any{"headers": wbaHeaders(signed.Header), "bodyBase64": encoded}
	default:
		return errJSON(fmt.Errorf("unknown WBA operation: %s", req.Operation))
	}
	return map[string]any{"ok": true, "message": output}
}
