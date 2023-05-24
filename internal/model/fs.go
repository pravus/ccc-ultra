package model

import (
	"io"
	"time"
)

type FsNode struct {
	Name     string
	IsDir    bool
	Modified time.Time
	MimeType string
	Size     int64
	Data     io.ReadCloser
	Nodes    []FsNode
}

type FsDriver interface {
	Get(string) (FsNode, error)
}

type FsWand interface {
	Zap(string) string
}
