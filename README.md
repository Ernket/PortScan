# 介绍
工具需要本地有`nmap`，因为扫描服务的时候会自动调用nmap识别端口服务<br>

# 使用方法：
```
Usage of port scanner:
Commands:
  portscan    Execute port scanning
    Options:
      -i string    Target IP address
      -r string    File containing IP addresses (*.txt)
      -t int       Number of threads (default 50)
      -n int       Start port number (default 1)
      -m int       End port number (default 65535)

  see         View scan results
    Options:
      -c string    Result file path (default "result.json")

Examples:
  ./scan portscan -i 192.168.1.1
  ./scan portscan -r ips.txt -t 100 -n 1 -m 1000
  ./scan see
  ./scan see -c custom_result.json
```
有两种模式，一种是portscan，这个是扫描端口的<br>
```
go run main.go portscan -r ip.txt
```
另一种是查看扫描结果（结果会保存为result.json，程序是根据result.json生成结果），`-h`解锁更多用法<br>
```
go run main.go see
```

# 效果展示
直接`-h`，可以看到完整的用法<br>
![](https://github.com/Ernket/PortScan/blob/main/png/ps1.png?raw=true)<br>
使用参数`--output-html`可以导出html，web服务识别到了会高亮
![](https://github.com/Ernket/PortScan/blob/main/png/ps2.png?raw=true)<br>
直接`see`，则在当前控制台输出所有<br>
![](https://github.com/Ernket/PortScan/blob/main/png/ps5.png?raw=true)<br>
也可以使用`--use`参数，在控制台进行交互<br>
![](https://github.com/Ernket/PortScan/blob/main/png/ps4.png?raw=true)<br>
