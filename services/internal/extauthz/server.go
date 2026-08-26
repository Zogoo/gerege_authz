// Package extauthz adapts Envoy's external authorization gRPC service to the
// decision pipeline.
//
// The adapter has one job beyond translation: make sure that nothing — a
// malformed request, a nil field, a panic — can produce an OK status. Envoy is
// configured with failOpen disabled, so a gRPC error also denies; but relying
// on that alone would leave the property outside this codebase, where no test
// can hold it.
package extauthz

import (
	"context"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/gerege/idp-mvp/internal/decision"
	"github.com/gerege/idp-mvp/internal/logx"
)

// Server implements envoy.service.auth.v3.Authorization.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	pipeline *decision.Pipeline
}

// New returns the gRPC service.
func New(p *decision.Pipeline) *Server { return &Server{pipeline: p} }

// Check is called by every Envoy sidecar and by the ingress gateway, once per
// request.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (resp *authv3.CheckResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			// An unhandled panic must not become a permit (mvp_docs/04 §6).
			logx.Error("panic in authorization check", "panic", r)
			resp = denied(500, logx.ReasonInternalError, `{"error":"access_denied","reason":"internal_error"}`, nil)
			err = nil
		}
	}()

	attrs := req.GetAttributes()
	http := attrs.GetRequest().GetHttp()
	if http == nil {
		logx.Error("check request carried no HTTP attributes")
		return denied(403, logx.ReasonInternalError, `{"error":"access_denied","reason":"internal_error"}`, nil), nil
	}

	headers := make(map[string]string, len(http.GetHeaders()))
	for k, v := range http.GetHeaders() {
		headers[strings.ToLower(k)] = v
	}

	out := s.pipeline.Check(ctx, decision.Request{
		Method:               http.GetMethod(),
		Path:                 http.GetPath(),
		Host:                 http.GetHost(),
		Scheme:               http.GetScheme(),
		Headers:              headers,
		SourcePrincipal:      attrs.GetSource().GetPrincipal(),
		DestinationPrincipal: attrs.GetDestination().GetPrincipal(),
		RequestID:            http.GetId(),
	})

	switch out.Outcome {
	case decision.Permit:
		return permitted(out.Headers), nil
	case decision.Redirect:
		h := map[string]string{"location": out.Location, "cache-control": "no-store"}
		if out.SetCookie != "" {
			h["set-cookie"] = out.SetCookie
		}
		return denied(out.Status, out.Reason, "", h), nil
	default:
		h := map[string]string{"content-type": "application/json", "x-authz-reason": out.Reason}
		for k, v := range out.Headers {
			h[k] = v
		}
		status := out.Status
		if status == 0 {
			status = 403
		}
		return denied(status, out.Reason, out.Body, h), nil
	}
}

func permitted(headers map[string]string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: headerOptions(headers)},
		},
	}
}

func denied(status int, reason, body string, headers map[string]string) *authv3.CheckResponse {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["x-authz-reason"] = reason
	return &authv3.CheckResponse{
		// Any non-OK gRPC status denies. The HTTP status the client sees comes
		// from DeniedResponse below.
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(status)},
				Headers: headerOptions(headers),
				Body:    body,
			},
		},
	}
}

func headerOptions(h map[string]string) []*corev3.HeaderValueOption {
	if len(h) == 0 {
		return nil
	}
	out := make([]*corev3.HeaderValueOption, 0, len(h))
	for k, v := range h {
		if v == "" {
			continue
		}
		out = append(out, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: k, Value: v},
		})
	}
	return out
}
