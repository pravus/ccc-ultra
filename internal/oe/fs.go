package oe

import (
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"ultra/internal/model"
)

type FsDriver struct {
	base  string
	index string
	wand  model.FsWand
}

var _ model.FsDriver = (*FsDriver)(nil)

func NewFsDriver(base string, index string, wand model.FsWand) FsDriver {
	if base != `` && base[len(base)-1] == '/' {
		base = base[:len(base)-2]
	}
	fs := FsDriver{
		base:  base,
		index: index,
		wand:  wand,
	}
	return fs
}

func (fs FsDriver) Get(path string) (model.FsNode, error) {
	target := fs.base
	if path != `/` {
		target += path
	}
	if info, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return model.FsNode{}, nil
		}
		return model.FsNode{}, err
	} else if info.IsDir() {
		return fs.dir(target, path, info)
	} else {
		return fs.file(target, path, info)
	}
}

func (fs FsDriver) dir(target string, rel string, info os.FileInfo) (model.FsNode, error) {
	if fs.index != `` {
		target := target + `/` + fs.index
		info, err := os.Stat(target)
		if err != nil {
			if !os.IsNotExist(err) {
				return model.FsNode{}, err
			}
		} else if !info.IsDir() {
			return fs.file(target, rel, info)
		}
	}
	list, err := ioutil.ReadDir(target)
	if err != nil {
		return model.FsNode{}, err
	}
	size := int64(len(list))
	if rel != `/` {
		size += 1
	}
	node := model.FsNode{
		Name:     info.Name(),
		IsDir:    true,
		Modified: info.ModTime(),
		Nodes:    make([]model.FsNode, size),
		Size:     size,
	}
	nodes := node.Nodes
	if rel != `/` {
		nodes[0] = model.FsNode{
			Name:     `..`,
			IsDir:    true,
			Modified: time.Now().UTC(),
		}
		nodes = nodes[1:]
	}
	for i, info := range list {
		name := info.Name()
		nodes[i] = model.FsNode{
			Name:     name,
			IsDir:    info.IsDir(),
			Modified: info.ModTime(),
			MimeType: fs.wand.Zap(name),
			Size:     info.Size(),
		}
	}
	sort.Slice(node.Nodes, func(one int, two int) bool {
		return strings.ToLower(node.Nodes[one].Name) < strings.ToLower(node.Nodes[two].Name)
	})
	return node, nil
}

func (fs FsDriver) file(target string, _ string, info os.FileInfo) (model.FsNode, error) {
	file, err := os.Open(target)
	if err != nil {
		return model.FsNode{}, err
	}
	name := info.Name()
	return model.FsNode{
		Name:     name,
		Modified: info.ModTime(),
		MimeType: fs.wand.Zap(name),
		Size:     info.Size(),
		Data:     file,
	}, nil
}
