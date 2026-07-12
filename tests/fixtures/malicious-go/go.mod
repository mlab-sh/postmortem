module github.com/acme/victim-go

go 1.21

// Typosquat of github.com/sirupsen/logrus. Pinned here for the scanner's test
// corpus only; the code in main.go is inert.
require github.com/sirupsen/logrous v1.9.3

require golang.org/x/sys v0.13.0 // indirect
