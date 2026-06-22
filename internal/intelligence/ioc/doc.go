// Package ioc implements the IOC store and matching engine.
// Supports IP, domain, URL, file hash, certificate, email, user agent,
// and registry key indicator types.
package ioc

// TODO: Implement IOC management:
// - In-memory IOC store with bloom filter for fast negative lookups
// - Ingestion from STIX/TAXII feeds, MISP exports, and manual input
// - IOC types: IP (v4/v6), domain, URL, file hash, cert thumbprint,
//   email, user agent, registry key
// - Matching against event stream in real-time
// - IOC expiration and confidence scoring
