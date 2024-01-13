// This one is mostly here to "prove" that Golang does not work.

package main

import (
  "io/ioutil"
  "log"
  "net/http"
)

func main() {
  resp, err := http.Get("https://www.google.com")
  if err != nil {
    log.Fatalln(err)
  }

  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    log.Fatalln(err)
  }

  log.Println(string(body))
}
