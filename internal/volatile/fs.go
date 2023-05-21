package volatile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"ultra/internal/model"
)

type FsDriver struct {
	root map[string]FsEntry
}

type FsEntry struct {
	data []byte
	node model.FsNode
}

var _ model.FsDriver = (*FsDriver)(nil)

func NewFsDriver() FsDriver {
	fs := FsDriver{
		root: map[string]FsEntry{},
	}
	return fs
}

func (fs FsDriver) Len() int {
	return len(fs.root)
}

func (fs FsDriver) Load(target string, name string, wand func([]byte) (string, error)) error {
	if _, ok := fs.root[target]; ok {
		return fmt.Errorf(`path "%s" already exists`, target)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	mimeType, err := wand(data)
	if err != nil {
		return err
	}
	_, name = path.Split(target)
	fs.root[target] = FsEntry{
		data: data,
		node: model.FsNode{
			Name:     name,
			IsDir:    false,
			Modified: time.Now().UTC(),
			MimeType: mimeType,
			Size:     int64(len(data)),
		},
	}
	return nil
}

func (fs FsDriver) Get(path string) (model.FsNode, error) {
	if meta, ok := fs.root[path]; !ok {
		return model.FsNode{}, fmt.Errorf(`not found`)
	} else {
		node := meta.node
		node.Data = io.NopCloser(bytes.NewBuffer(meta.data))
		return node, nil
	}
}
