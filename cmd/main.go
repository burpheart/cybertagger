package main

import (
	"cybertagger"
	"os"
)

func main() {
	//源文件 src  保存文件 dst  任务id taskid
	cybertagger.RunNew(true, os.Args[1], os.Args[2], os.Args[3])

}
