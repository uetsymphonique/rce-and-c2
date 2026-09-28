package util

import (
    "fmt"
    "os"
    "path/filepath"
)

var (
    ProjectRoot string
    UploadDir   string
)

func init() {
    SetRootDirectories()
}

func SetRootDirectories() {
    var err error
    ProjectRoot, err = os.Getwd()
    if err != nil {
        panic(err)
    }
    UploadDir = filepath.Join(ProjectRoot, "files")

    // Auto-create the upload directory. HandleFileUpload opens dest files
    // with O_CREATE but ENOENT still kills the open when the directory
    // itself is missing, and the task is still marked FINISHED - silently
    // losing all uploaded content (observed: files/ wiped by git clean
    // mid-run, hex0-hex3 "uploaded" successfully with zero bytes on disk).
    if err := os.MkdirAll(UploadDir, 0755); err != nil {
        panic(fmt.Sprintf("failed to create upload dir %s: %s", UploadDir, err.Error()))
    }
}
