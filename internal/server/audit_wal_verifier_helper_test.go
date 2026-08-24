package server

import "os"

// corruptAuditWALTail appends a record that is not part of the chain, which is
// what a tamper-evident log exists to detect.
func corruptAuditWALTail(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(`{"seq":9999,"prev_hash":"nope","hash":"nope","event":{"id":"x"}}` + "\n")
	return err
}
