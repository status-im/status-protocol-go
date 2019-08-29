// Code generated by go-bindata. DO NOT EDIT.
// sources:
// 000001_init.down.db.sql (82B)
// 000001_init.up.db.sql (840B)
// 000002_add_chats.down.db.sql (74B)
// 000002_add_chats.up.db.sql (541B)
// 000003_add_contacts.down.db.sql (21B)
// 000003_add_contacts.up.db.sql (251B)
// 000004_user_messages_compatibility.down.sql (33B)
// 000004_user_messages_compatibility.up.sql (928B)
// doc.go (377B)

package migrations

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var __000001_initDownDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x72\x09\xf2\x0f\x50\x08\x71\x74\xf2\x71\x55\x28\x2d\x4e\x2d\x8a\xcf\x4d\x2d\x2e\x4e\x4c\x4f\x2d\xb6\xe6\x42\x92\xc9\x4d\xcd\x4d\x4a\x2d\x2a\xce\xc8\x2c\x88\x2f\x2d\x48\x49\x2c\x41\x93\x4e\xce\x48\x2c\x89\x87\xaa\xb1\xe6\x02\x04\x00\x00\xff\xff\x69\x98\x5e\xa1\x52\x00\x00\x00")

func _000001_initDownDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000001_initDownDbSql,
		"000001_init.down.db.sql",
	)
}

func _000001_initDownDbSql() (*asset, error) {
	bytes, err := _000001_initDownDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000001_init.down.db.sql", size: 82, mode: os.FileMode(0644), modTime: time.Unix(1564235168, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xe8, 0x5f, 0xe0, 0x6, 0xfc, 0xed, 0xb7, 0xff, 0xb5, 0xf3, 0x33, 0x45, 0x1, 0x5b, 0x84, 0x80, 0x74, 0x60, 0x81, 0xa6, 0x8b, 0xb4, 0xd4, 0xad, 0x10, 0xa8, 0xb3, 0x61, 0x6f, 0xc5, 0x2f, 0xaa}}
	return a, nil
}

var __000001_initUpDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x52\xb1\x6e\xc2\x30\x14\xdc\xf3\x15\x6f\x24\x12\x43\xf7\x4e\x0e\xbc\x80\xd5\xd4\x6e\x1d\xa7\xc0\x14\x19\xe2\x82\x0b\x09\x11\x36\x52\xf9\xfb\xaa\x49\x8c\x02\x45\x15\xac\xef\xce\xe7\xbb\x7b\x6f\x24\x90\x48\x04\x49\xa2\x04\x81\xc6\xc0\xb8\x04\x9c\xd3\x54\xa6\x70\xb4\xfa\x90\x97\xda\x5a\xb5\xd6\x16\x06\x01\x00\x80\x29\x20\x4a\x78\x04\x19\xa3\xef\x19\x36\x6c\x96\x25\xc9\xb0\x01\x57\x1b\xe5\x72\x53\xc0\x07\x11\xa3\x29\x11\xd7\xe8\xbe\x72\xba\x72\xb9\x3b\xd5\xda\x53\x5a\xa4\xfb\xe3\x06\xe2\xf4\xb7\x03\x89\x73\xd9\x49\xec\xf6\xab\x2d\x44\x74\x42\x59\x37\x71\xa6\xd4\xd6\xa9\xb2\xbe\x98\xfa\xaf\xbc\xa1\x9e\x82\x37\x71\x29\x5c\x1f\x97\x3b\xb3\xca\xb7\xfa\xd4\xc4\x6b\x87\x9f\x3b\xb5\xb6\x40\x99\x3c\x07\x81\x31\xc6\x24\x4b\x24\x3c\x05\xe1\x73\x10\x74\xdd\x51\x36\xc6\xb9\x0f\x6f\x81\xb3\xcb\xe6\x06\x1d\xd2\x7b\x71\xab\xed\x52\x97\x4b\x7d\xb0\x1b\x53\xe7\xc7\xba\x50\xae\x5f\xb9\x2f\xf4\x4d\xd0\x57\x22\x16\xf0\x82\x8b\xab\x72\x0b\xe5\x54\xbb\x99\x47\x56\x12\x73\x81\x74\xc2\x1a\xbd\xb3\x4d\x10\x18\xa3\x40\x36\xc2\xb4\x79\x6e\x07\xa6\x08\x83\x10\x66\x54\x4e\x79\x26\x41\xf0\x19\x1d\xff\x9f\xa5\x91\xea\x02\x75\x29\xae\x1a\x7e\xc8\xa6\x2a\x4a\x53\x41\xc4\x79\x82\x84\xfd\x5d\x46\x4c\x92\x14\x5b\xe6\xd7\xde\x54\xba\xb8\x8b\x7a\x7f\xf6\x96\xdf\x5e\xbc\x67\x0e\x7b\x81\xc2\xdf\x63\xf8\x09\x00\x00\xff\xff\x66\xab\x2d\x2f\x48\x03\x00\x00")

func _000001_initUpDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000001_initUpDbSql,
		"000001_init.up.db.sql",
	)
}

func _000001_initUpDbSql() (*asset, error) {
	bytes, err := _000001_initUpDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000001_init.up.db.sql", size: 840, mode: os.FileMode(0644), modTime: time.Unix(1567098004, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xe7, 0x27, 0x96, 0x3b, 0x72, 0x81, 0x7d, 0xba, 0xa4, 0xfb, 0xf7, 0x4, 0xd, 0x6f, 0xc8, 0x30, 0xfe, 0x47, 0xe0, 0x9, 0xf, 0x43, 0x13, 0x6, 0x55, 0xfc, 0xee, 0x15, 0x69, 0x99, 0x53, 0x3f}}
	return a, nil
}

var __000002_add_chatsDownDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x72\x09\xf2\x0f\x50\x08\x71\x74\xf2\x71\x55\xc8\x4d\xcd\x4d\x4a\x2d\x2a\xce\xc8\x2c\x88\x2f\x2d\x48\x49\x2c\x49\x2d\xb6\xe6\x42\x92\x4e\xce\x48\x2c\x89\x87\xaa\xc1\x90\x28\xb6\xe6\x02\x04\x00\x00\xff\xff\xde\x59\xf6\x29\x4a\x00\x00\x00")

func _000002_add_chatsDownDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000002_add_chatsDownDbSql,
		"000002_add_chats.down.db.sql",
	)
}

func _000002_add_chatsDownDbSql() (*asset, error) {
	bytes, err := _000002_add_chatsDownDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000002_add_chats.down.db.sql", size: 74, mode: os.FileMode(0644), modTime: time.Unix(1565859748, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xd3, 0xa7, 0xf0, 0x94, 0x7a, 0x9, 0xdc, 0x6c, 0x7b, 0xdc, 0x12, 0x30, 0x55, 0x31, 0x17, 0xf2, 0xcc, 0x6e, 0xfd, 0xbb, 0x70, 0xb9, 0xd8, 0x9f, 0x81, 0x83, 0xdc, 0x1d, 0x1c, 0x3a, 0x8d, 0xce}}
	return a, nil
}

var __000002_add_chatsUpDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x91\x4f\x4b\x03\x31\x10\xc5\xef\xf3\x29\x06\x3c\x54\x61\x0f\x7a\x10\x85\x9e\xb2\xdb\x14\x17\xe3\xa6\xa4\xa9\xd8\x53\x48\xb3\x83\x5d\xba\xff\x68\xb2\x95\x7e\x7b\x69\x5d\xda\xea\x2a\x78\x4c\xde\xef\xbd\x49\xe6\x25\x8a\x33\xcd\x51\xb3\x58\x70\x4c\xa7\x98\x49\x8d\xfc\x2d\x9d\xeb\x39\xba\xb5\x0d\x1e\xaf\xa1\xc8\xf1\x95\xa9\xe4\x89\x29\x9c\xa9\xf4\x85\xa9\x25\x3e\xf3\x25\xca\x0c\x13\x99\x4d\x45\x9a\x68\x54\x7c\x26\x58\xc2\x23\xa8\x6d\x45\x27\xfa\x90\x95\x2d\x84\x88\xc0\x35\x65\xb3\x1d\xdc\xe3\x84\x4f\xd9\x42\x68\x1c\x5d\xd9\xbb\xc7\x87\xfc\x7e\x14\x41\xd8\xb7\x84\x69\xa6\x2f\xcc\xd6\x85\x62\x47\x18\x4b\x29\x38\xcb\x86\x6e\xad\x16\x3c\x82\x50\x54\xe4\x83\xad\xda\x1f\xee\x9c\x4a\x0a\x94\x1b\x1b\x8c\x2b\x1b\xb7\x31\x3b\x5b\x76\xdf\x47\x9c\x92\x6e\x23\x68\xbb\x55\x59\x38\xb3\xa1\x3d\xc6\x42\xc6\x11\x74\xf5\xae\xa0\x0f\xca\x4d\x45\xde\xdb\x77\x32\xae\xe9\xea\xf0\xa7\xbf\xb4\xfe\x7f\x83\x8e\xe0\x39\xb3\x0e\x54\x07\x73\xfc\x7d\xbf\xa6\xdf\x91\xb3\x5a\x51\xb5\xa2\xad\xef\x9f\xd9\x9f\xd6\x45\x6b\xba\x36\xb7\x81\xbe\x04\xb8\x19\x03\xc0\x44\xc9\x59\x5f\xf1\x90\x1b\x5f\xca\x87\xce\x4d\xcf\x8c\xe1\x33\x00\x00\xff\xff\xf3\xb4\xa4\xad\x1d\x02\x00\x00")

func _000002_add_chatsUpDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000002_add_chatsUpDbSql,
		"000002_add_chats.up.db.sql",
	)
}

func _000002_add_chatsUpDbSql() (*asset, error) {
	bytes, err := _000002_add_chatsUpDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000002_add_chats.up.db.sql", size: 541, mode: os.FileMode(0644), modTime: time.Unix(1565859748, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xd, 0x7f, 0x3a, 0xd7, 0xf6, 0x8b, 0x6e, 0x4d, 0xce, 0x7d, 0x63, 0x1d, 0x30, 0xa2, 0xc1, 0xb, 0xa0, 0x35, 0x2e, 0xfa, 0xef, 0xf0, 0x39, 0xf7, 0x22, 0xdd, 0x31, 0x11, 0xb1, 0xff, 0xbf, 0xb3}}
	return a, nil
}

var __000003_add_contactsDownDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x72\x09\xf2\x0f\x50\x08\x71\x74\xf2\x71\x55\x48\xce\xcf\x2b\x49\x4c\x2e\x29\xb6\xe6\x02\x04\x00\x00\xff\xff\x66\x64\xd9\xdd\x15\x00\x00\x00")

func _000003_add_contactsDownDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000003_add_contactsDownDbSql,
		"000003_add_contacts.down.db.sql",
	)
}

func _000003_add_contactsDownDbSql() (*asset, error) {
	bytes, err := _000003_add_contactsDownDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000003_add_contacts.down.db.sql", size: 21, mode: os.FileMode(0644), modTime: time.Unix(1565860010, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xfc, 0x7e, 0xb, 0xec, 0x72, 0xcd, 0x21, 0x3e, 0xa2, 0x38, 0xe0, 0x95, 0x7e, 0xce, 0x4a, 0x17, 0xc8, 0xd0, 0x1c, 0xfa, 0xa3, 0x23, 0x5, 0xab, 0x89, 0xf9, 0xfc, 0x63, 0x7, 0x28, 0xe9, 0x93}}
	return a, nil
}

var __000003_add_contactsUpDbSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x64\xcd\xc1\x4a\xc4\x30\x14\x85\xe1\x7d\x9e\xe2\x2c\x15\x5c\xb8\x77\x95\xc6\x3b\x50\x8c\xc9\x10\x32\xe0\xac\x42\x6c\xa2\x06\xa7\x4d\x69\x6e\x05\xdf\x5e\x8a\xa0\x0c\xdd\x7e\xe7\x87\xa3\x1c\x49\x4f\xf0\xb2\xd3\x84\xa1\x4e\x1c\x07\x6e\xb8\x11\x40\x49\xf0\xf4\xe2\x71\x74\xfd\xb3\x74\x67\x3c\xd1\x19\xd6\x40\x59\x73\xd0\xbd\xf2\x70\x74\xd4\x52\xd1\x9d\x00\x62\x4a\x4b\x6e\xed\xb7\x37\xd6\xc3\x9c\xb4\xde\x86\x29\x8e\x79\xaf\xf3\x47\xe5\xba\xe7\x4b\x6c\x1c\xd6\x39\x45\xce\x09\xbd\xf9\x1f\xf1\x48\x07\x79\xd2\x1e\xf7\x5b\xd6\xbe\x1b\xe7\x31\x70\x7c\x6f\xe8\xb4\xed\x36\x4b\xf9\xab\x0c\x39\x94\xe9\xad\xfe\x19\x2f\xe5\x75\xe5\x1c\xb8\x06\x8e\x97\xcf\xeb\x3f\x71\xfb\x20\x7e\x02\x00\x00\xff\xff\xc3\x2e\x5b\xed\xfb\x00\x00\x00")

func _000003_add_contactsUpDbSqlBytes() ([]byte, error) {
	return bindataRead(
		__000003_add_contactsUpDbSql,
		"000003_add_contacts.up.db.sql",
	)
}

func _000003_add_contactsUpDbSql() (*asset, error) {
	bytes, err := _000003_add_contactsUpDbSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000003_add_contacts.up.db.sql", size: 251, mode: os.FileMode(0644), modTime: time.Unix(1565860010, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x8f, 0x19, 0x9f, 0x5c, 0x9d, 0xa1, 0xe5, 0x99, 0xbe, 0x47, 0xce, 0xa5, 0xd3, 0x51, 0x2f, 0x9b, 0x1d, 0xd9, 0x3f, 0x7a, 0xbf, 0xf, 0x76, 0x6b, 0x4f, 0x82, 0xbd, 0x13, 0x9d, 0x25, 0xdd, 0x60}}
	return a, nil
}

var __000004_user_messages_compatibilityDownSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x72\x09\xf2\x0f\x50\x08\x71\x74\xf2\x71\x55\x28\x2d\x4e\x2d\x8a\xcf\x4d\x2d\x2e\x4e\x4c\x4f\x2d\x8e\xcf\x49\x4d\x4f\x4c\xae\xb4\xe6\x02\x04\x00\x00\xff\xff\x25\xef\xa4\x66\x21\x00\x00\x00")

func _000004_user_messages_compatibilityDownSqlBytes() ([]byte, error) {
	return bindataRead(
		__000004_user_messages_compatibilityDownSql,
		"000004_user_messages_compatibility.down.sql",
	)
}

func _000004_user_messages_compatibilityDownSql() (*asset, error) {
	bytes, err := _000004_user_messages_compatibilityDownSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000004_user_messages_compatibility.down.sql", size: 33, mode: os.FileMode(0644), modTime: time.Unix(1565860010, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xb9, 0xaf, 0x48, 0x80, 0x3d, 0x54, 0x5e, 0x53, 0xee, 0x98, 0x26, 0xbb, 0x99, 0x6a, 0xd8, 0x37, 0x94, 0xf2, 0xf, 0x82, 0xfa, 0xb7, 0x6a, 0x68, 0xcd, 0x8b, 0xe2, 0xc4, 0x6, 0x25, 0xdc, 0x6}}
	return a, nil
}

var __000004_user_messages_compatibilityUpSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x92\xcf\x6e\x9b\x4c\x14\xc5\xf7\x7e\x8a\xb3\xb3\x2d\x99\x4f\x59\x44\xd9\x64\x85\x9d\xf1\x57\x54\x0a\x11\xc6\x55\xb2\x1a\x8d\xf1\xad\x19\x15\x66\xac\x99\x4b\x5d\xa4\x3c\x7c\x85\xc1\x51\x70\x9d\x55\x59\xb0\x98\xdf\x39\x33\xe7\xfe\x09\x02\x44\x3c\xf5\xd0\xf5\xd1\x3a\x56\x86\xc1\xa5\xea\x7e\xda\x83\xd5\xae\x22\x94\xca\xc3\xd9\x93\xde\x43\x79\x9c\x08\x8e\xaa\x16\xd6\x40\xf3\x24\x08\x70\x2a\xc9\x74\xe6\x8a\x6a\x32\xac\xcd\x01\xda\xfc\xd0\x46\x33\x05\xbe\x70\xb6\xaa\xfe\x9b\xac\x32\x11\xe6\x02\x79\xb8\x8c\x05\xa2\x35\x92\x34\x87\x78\x89\x36\xf9\x06\x8d\x27\x27\x6b\xf2\x5e\x1d\xc8\xcb\x8a\x0e\xaa\x68\x31\x9b\x00\x80\xde\xe3\x7b\x98\xad\xbe\x84\x19\x9e\xb3\xe8\x5b\x98\xbd\xe2\xab\x78\x45\x9a\x60\x95\x26\xeb\x38\x5a\xe5\xc8\xc4\x73\x1c\xae\xc4\xe2\xac\x3f\x95\xda\x1f\xc9\x49\xd6\x35\x79\x56\xf5\x11\x51\x92\x8b\xff\x45\x76\x7e\x2f\xd9\xc6\x71\xaf\xf3\xb6\x71\x05\x61\x19\xa7\xcb\x2b\xb2\x27\xcf\xda\x28\xd6\xd6\x9c\x71\x7f\x5a\x58\xc3\x64\xf8\x3d\xcc\xd8\x33\x50\xc9\xed\x91\x3e\x91\x74\x35\x1a\x55\xbf\xe3\xfe\x74\x14\xf3\xfa\xd2\x52\xb1\xfc\x50\xff\x98\x3a\x62\xd7\xca\xc2\x36\x86\x47\x5e\x3c\x89\x75\xb8\x8d\x73\xdc\x5d\x74\xc7\xaa\x95\x6c\xc7\xef\x0e\xcd\x1e\x05\x1e\x13\xcf\x8a\x1b\x3f\x66\x45\x65\x8b\x9f\xf2\x97\xaa\x1a\xba\x91\xd7\x97\xf6\x84\x65\x9a\xc6\x22\x4c\xfe\x8e\x93\x67\xdb\x61\x44\x9e\xc8\x7c\xae\x5b\x87\xf1\x66\x10\xda\x86\x0f\x56\x9b\xc3\x55\x96\xc9\xfc\x71\x72\xd9\xa6\x28\x79\x12\x2f\xd0\xfb\xdf\x72\x18\x68\x9a\xdc\xdc\xa6\x59\x8f\xe7\x8f\x37\x8c\xa4\x5c\x51\xca\x5d\x2b\x2f\x0d\x4f\x13\xdc\xbe\xa4\x8f\xdf\xec\x3c\xbb\xd9\xf4\xee\x1f\xbf\x29\xde\xde\x3e\x76\x74\x81\xe0\xe1\x7e\x81\x87\xfb\x79\x07\xf4\x7e\x71\x59\x80\xae\xde\x3f\x01\x00\x00\xff\xff\xba\x8f\x77\x72\xa0\x03\x00\x00")

func _000004_user_messages_compatibilityUpSqlBytes() ([]byte, error) {
	return bindataRead(
		__000004_user_messages_compatibilityUpSql,
		"000004_user_messages_compatibility.up.sql",
	)
}

func _000004_user_messages_compatibilityUpSql() (*asset, error) {
	bytes, err := _000004_user_messages_compatibilityUpSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "000004_user_messages_compatibility.up.sql", size: 928, mode: os.FileMode(0644), modTime: time.Unix(1566366197, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xdf, 0xc4, 0x5c, 0xed, 0x4, 0x26, 0xb1, 0xb2, 0x53, 0xac, 0x1, 0x20, 0xf3, 0x17, 0x37, 0xb3, 0x3d, 0x84, 0x5e, 0xd8, 0x1, 0x53, 0x88, 0x9a, 0x9c, 0xaf, 0x9, 0xdf, 0x58, 0x2e, 0xf0, 0x19}}
	return a, nil
}

var _docGo = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x84\x8f\xbb\x6e\xc3\x30\x0c\x45\x77\x7f\xc5\x45\x96\x2c\xb5\xb4\x74\xea\xd6\xb1\x7b\x7f\x80\x91\x68\x89\x88\x1e\xae\x48\xe7\xf1\xf7\x85\xd3\x02\xcd\xd6\xf5\x00\xe7\xf0\xd2\x7b\x7c\x66\x51\x2c\x52\x18\xa2\x68\x1c\x58\x95\xc6\x1d\x27\x0e\xb4\x29\xe3\x90\xc4\xf2\x76\x72\xa1\x57\xaf\x46\xb6\xe9\x2c\xd5\x57\x49\x83\x8c\xfd\xe5\xf5\x30\x79\x8f\x40\xed\x68\xc8\xd4\x62\xe1\x47\x4b\xa1\x46\xc3\xa4\x25\x5c\xc5\x32\x08\xeb\xe0\x45\x6e\x0e\xef\x86\xc2\xa4\x06\xcb\x64\x47\x85\x65\x46\x20\xe5\x3d\xb3\xf4\x81\xd4\xe7\x93\xb4\x48\x46\x6e\x47\x1f\xcb\x13\xd9\x17\x06\x2a\x85\x23\x96\xd1\xeb\xc3\x55\xaa\x8c\x28\x83\x83\xf5\x71\x7f\x01\xa9\xb2\xa1\x51\x65\xdd\xfd\x4c\x17\x46\xeb\xbf\xe7\x41\x2d\xfe\xff\x11\xae\x7d\x9c\x15\xa4\xe0\xdb\xca\xc1\x38\xba\x69\x5a\x29\x9c\x29\x31\xf4\xab\x88\xf1\x34\x79\x9f\xfa\x5b\xe2\xc6\xbb\xf5\xbc\x71\x5e\xcf\x09\x3f\x35\xe9\x4d\x31\x77\x38\xe7\xff\x80\x4b\x1d\x6e\xfa\x0e\x00\x00\xff\xff\x9d\x60\x3d\x88\x79\x01\x00\x00")

func docGoBytes() ([]byte, error) {
	return bindataRead(
		_docGo,
		"doc.go",
	)
}

func docGo() (*asset, error) {
	bytes, err := docGoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "doc.go", size: 377, mode: os.FileMode(0644), modTime: time.Unix(1564235168, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0xef, 0xaf, 0xdf, 0xcf, 0x65, 0xae, 0x19, 0xfc, 0x9d, 0x29, 0xc1, 0x91, 0xaf, 0xb5, 0xd5, 0xb1, 0x56, 0xf3, 0xee, 0xa8, 0xba, 0x13, 0x65, 0xdb, 0xab, 0xcf, 0x4e, 0xac, 0x92, 0xe9, 0x60, 0xf1}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"000001_init.down.db.sql": _000001_initDownDbSql,

	"000001_init.up.db.sql": _000001_initUpDbSql,

	"000002_add_chats.down.db.sql": _000002_add_chatsDownDbSql,

	"000002_add_chats.up.db.sql": _000002_add_chatsUpDbSql,

	"000003_add_contacts.down.db.sql": _000003_add_contactsDownDbSql,

	"000003_add_contacts.up.db.sql": _000003_add_contactsUpDbSql,

	"000004_user_messages_compatibility.down.sql": _000004_user_messages_compatibilityDownSql,

	"000004_user_messages_compatibility.up.sql": _000004_user_messages_compatibilityUpSql,

	"doc.go": docGo,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"000001_init.down.db.sql":                     &bintree{_000001_initDownDbSql, map[string]*bintree{}},
	"000001_init.up.db.sql":                       &bintree{_000001_initUpDbSql, map[string]*bintree{}},
	"000002_add_chats.down.db.sql":                &bintree{_000002_add_chatsDownDbSql, map[string]*bintree{}},
	"000002_add_chats.up.db.sql":                  &bintree{_000002_add_chatsUpDbSql, map[string]*bintree{}},
	"000003_add_contacts.down.db.sql":             &bintree{_000003_add_contactsDownDbSql, map[string]*bintree{}},
	"000003_add_contacts.up.db.sql":               &bintree{_000003_add_contactsUpDbSql, map[string]*bintree{}},
	"000004_user_messages_compatibility.down.sql": &bintree{_000004_user_messages_compatibilityDownSql, map[string]*bintree{}},
	"000004_user_messages_compatibility.up.sql":   &bintree{_000004_user_messages_compatibilityUpSql, map[string]*bintree{}},
	"doc.go": &bintree{docGo, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
