## 这是什么
模拟cobalt strike的execute-assembly功能，将.net assembly注入到目标进程。


## 使用
inject_memory_assembly.exe pid assembly_path [assembly_arg1] [assembly_arg2] [assembly_arg3]


## 原理
1. 通过dll反射注入将unmanaged dll注入到目标进程，unmanaged dll用来内存加载assembly
2. 将assembly写入到目标进程，获取assembly的大小和在目标进程的地址
3. 写入assembly的地址和大小以及传递给assembly的参数信息到目标进程
4. 执行unmanaged dll的导出函数LoadAssembly2 进行.net assembly内存加载


## 感谢
- [InMemoryNET](https://github.com/mez-0/InMemoryNET)
- [metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly)


