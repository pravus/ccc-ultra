package volatile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"time"
)

type Fs struct {
	root map[string]FsEntry
}

type FsEntry struct {
	Name string
	When time.Time
	Mime string
	Data []byte
}

func NewFs() Fs {
	fs := Fs{
		root: map[string]FsEntry{},
	}
	return fs
}

func (fs Fs) Len() int {
	return len(fs.root)
}

func (fs Fs) FromFile(target string, name string, wand func([]byte) (string, error)) error {
	if _, ok := fs.root[target]; ok {
		return fmt.Errorf(`path "%s" already exists`, target)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	mime, err := wand(data)
	if err != nil {
		return err
	}
	_, name = path.Split(target)
	fs.root[target] = FsEntry{
		Name: name,
		When: time.Now().UTC(),
		Mime: mime,
		Data: data,
	}
	return nil
}

func (fs Fs) At(target string) (FsEntry, error) {
	if entry, ok := fs.root[target]; !ok {
		return FsEntry{}, fmt.Errorf(`path "%s" not found`, target)
	} else {
		return entry, nil
	}
}

func (entry FsEntry) ReadCloser() io.ReadCloser {
	return io.NopCloser(bytes.NewBuffer(entry.Data))
}
