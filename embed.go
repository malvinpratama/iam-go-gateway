// Package gateway holds the embedded API docs (OpenAPI spec + Swagger UI) served
// by the gateway at /openapi.yaml and /docs.
package gateway

import "embed"

// OpenAPISpec is the OpenAPI 3 document for the REST API.
//
//go:embed openapi.yaml
var OpenAPISpec []byte

// SwaggerUI holds the vendored Swagger UI assets (self-contained, no CDN).
//
//go:embed swaggerui
var SwaggerUI embed.FS
