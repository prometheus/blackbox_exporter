package probers

import (
  "net/http"
)

var Probers = make(map[string]func(string, http.ResponseWriter)(bool))
