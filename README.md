# sshkeygen

This library generate ssh public/private keys with Go.

Generated Public/Private keys are byte array.

## Usage

```go
package main

import (
	"fmt"
	"unsafe"

	sshkey "github.com/kenzo0107/sshkeygen"
)

func main() {
	// generate ssh key
	s := sshkey.New().BitSize(4096).KeyBytes().Gen()
	fmt.Printf("PublicKeyBytes: %#v\n", s.PublicKeyBytes())
	fmt.Printf("PrivateKeyBytes: %#v\n", s.PrivateKeyBytes())

	// []byte to string
	d := s.PublicKeyBytes()
	t := *(*string)(unsafe.Pointer(&d))
	fmt.Printf("PublicKeyBytes: %#v\n", t)
}
```

## License

MIT
