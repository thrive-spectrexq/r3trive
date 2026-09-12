package api

import (
	"net/http"
)

// OpenAPISpecJSON is the OpenAPI 3.0 specification for R3TRIVE REST API.
const OpenAPISpecJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "R3TRIVE API",
    "description": "Enterprise Endpoint Detection, Threat Hunting and Automated Defense REST API",
    "version": "1.0.0",
    "contact": {
      "name": "R3TRIVE Project",
      "url": "https://github.com/thrive-spectrexq/r3trive"
    }
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "Primary API Server"
    }
  ],
  "components": {
    "securitySchemes": {
      "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
      },
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer"
      }
    }
  },
  "security": [
    {
      "ApiKeyAuth": []
    },
    {
      "BearerAuth": []
    }
  ],
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "description": "Returns status of the server and storage engine",
        "responses": {
          "200": { "description": "System operational" }
        }
      }
    },
    "/events": {
      "get": {
        "summary": "Query observable telemetry events",
        "parameters": [
          { "name": "type", "in": "query", "schema": { "type": "string" } },
          { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 100 } }
        ],
        "responses": {
          "200": { "description": "List of matched events" }
        }
      }
    },
    "/alerts": {
      "get": {
        "summary": "List generated security alerts",
        "responses": {
          "200": { "description": "Array of alerts" }
        }
      }
    },
    "/incidents": {
      "get": {
        "summary": "List correlated incidents",
        "responses": {
          "200": { "description": "Array of incidents" }
        }
      }
    },
    "/hosts": {
      "get": {
        "summary": "List monitored fleet hosts",
        "responses": {
          "200": { "description": "Array of registered hosts" }
        }
      },
      "post": {
        "summary": "Register or heartbeat a fleet host",
        "responses": {
          "201": { "description": "Host registered successfully" }
        }
      }
    },
    "/rules": {
      "get": {
        "summary": "List active correlation rules",
        "responses": {
          "200": { "description": "Array of rules" }
        }
      },
      "post": {
        "summary": "Create a new correlation rule",
        "responses": {
          "201": { "description": "Rule created" }
        }
      }
    },
    "/iocs": {
      "get": {
        "summary": "Query indicator of compromise records",
        "responses": {
          "200": { "description": "Array of IOCs" }
        }
      },
      "post": {
        "summary": "Ingest a new threat indicator",
        "responses": {
          "201": { "description": "IOC created" }
        }
      }
    },
    "/response/execute": {
      "post": {
        "summary": "Execute or simulate a containment defense action",
        "responses": {
          "200": { "description": "Action execution result" }
        }
      }
    }
  }
}`

// SwaggerUIHTML is a lightweight standalone HTML page rendering the Swagger UI via CDN.
const SwaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>R3TRIVE API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; background: #fafafa; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/api/v1/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ]
      });
    };
  </script>
</body>
</html>`

// HandleOpenAPIJSON serves the raw OpenAPI 3.0 specification.
func HandleOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(OpenAPISpecJSON))
}

// HandleSwaggerUI serves the interactive Swagger UI page.
func HandleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(SwaggerUIHTML))
}
