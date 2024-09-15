# httpsigver-ap


`httpsigver-ap` is a Go library allowing everyone to easily add Mastodon/ActivityPub-compatible HTTP signature to any HTTP request as well 
as verify the validity of a request's signature originating from an ActivityPub server.  

## Usage

[![Go Reference](https://pkg.go.dev/badge/github.com/MatejLach/httpsigver-ap.svg)](https://pkg.go.dev/github.com/MatejLach//httpsigver-ap#section-documentation)

### Signing requests

```go
package main

import (
	//...
	
	"github.com/MatejLach/httpsigver-ap"
)

func main() {
	// ...
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/user/me", server.URL), nil)
	if err != nil {
		// error handling
	}

	reqActorPubKeyId, err := url.Parse(fmt.Sprintf("%s/user/me", server.URL))
	if err != nil {
		// error handling
	}

	err = httpsigver.SignRequest(context.Background(), req, reqActorPubKeyId, privateKeyPem.String())
	if err != nil {
		// error handling
	}
}
```

### Verifying requests

```go
package main

import (
	//...
	
	"github.com/MatejLach/httpsigver-ap"
)

func main() {
	// ...
	validSignature, err := httpsigver.ReqHasValidSignature(context.Background(), req, "", true)
	if err != nil { 
		// error handling
	}
}
```

See the test suite for a more complete example. 

## Contributing

Pull requests and bug reports are welcome.
