package main

import (
	"net"
	"net/http"
)

func probeTCP(target string, w http.ResponseWriter, module Module) (success bool) {
	conn, err := net.DialTimeout("tcp", target, module.Timeout)
	if err == nil {
		success = true
		conn.Close()
	}
	return
}
