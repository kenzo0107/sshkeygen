package main

import (
	"fmt"

	sshkey "github.com/kenzo0107/sshkeygen"
)

func main() {
	s := sshkey.New().BitSize(4096).KeyGen()
	fmt.Println(s.PublicKeyStr())
}
