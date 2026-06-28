package checker

import (
	"io"
	"os"
)

func readAtMost(r io.Reader, buf []byte) (int, error) {
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, nil
}

func stderr() io.Writer { return os.Stderr }
