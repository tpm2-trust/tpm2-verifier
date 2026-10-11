// Package vendors embeds the curated TPM vendor trust store.
//
// Every vendor lives in its own directory:
//
//	<vendor>/vendor.yaml        metadata and certificate manifest (sha256, source URL)
//	<vendor>/README.md          human readable notes about the vendor's PKI
//	<vendor>/roots/*.der        trust anchors
//	<vendor>/intermediates/*.der static intermediates published by the vendor
//
// Use package store to load and validate it.
package vendors

import "embed"

// FS holds all vendor directories.
//
//go:embed */vendor.yaml */README.md */roots */intermediates
var FS embed.FS
