package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/manifoldco/promptui"
)

type ScanResult struct {
	IP       string    `json:"ip"`
	Port     int       `json:"port"`
	Finger   string    `json:"finger"`
	ScanTime time.Time `json:"scan_time"`
}

type ResultStore struct {
	mu      sync.Mutex
	results []ScanResult
	file    string
}

func NewResultStore(filename string) *ResultStore {
	return &ResultStore{
		results: make([]ScanResult, 0),
		file:    filename,
	}
}

func (rs *ResultStore) Add(result ScanResult) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// 检查是否已存在该记录
	for i, r := range rs.results {
		if r.IP == result.IP && r.Port == result.Port {
			rs.results[i] = result
			return rs.save()
		}
	}

	rs.results = append(rs.results, result)
	return rs.save()
}

func (rs *ResultStore) save() error {
	file, err := os.Create(rs.file)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(rs.results)
}

func (rs *ResultStore) Load() error {
	// 检查文件是否存在
	if _, err := os.Stat(rs.file); os.IsNotExist(err) {
		return nil
	}

	file, err := os.OpenFile(rs.file, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	// 检查文件是否为空
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() == 0 {
		return nil
	}

	decoder := json.NewDecoder(file)
	return decoder.Decode(&rs.results)
}

func printHelp() {
	fmt.Println("Usage of port scanner:")
	fmt.Println("Commands:")
	fmt.Println("  portscan    Execute port scanning")
	fmt.Println("    Options:")
	fmt.Println("      -i string    Target IP address")
	fmt.Println("      -r string    File containing IP addresses (*.txt)")
	fmt.Println("      -t int       Number of threads (default 50)")
	fmt.Println("      -n int       Start port number (default 1)")
	fmt.Println("      -m int       End port number (default 65535)")
	fmt.Println("\n  see         View scan results")
	fmt.Println("    Options:")
	fmt.Println("      -c string    Result file path (default \"result.json\")")
	fmt.Println("\nExamples:")
	fmt.Println("  ./scan portscan -i 192.168.1.1")
	fmt.Println("  ./scan portscan -r ips.txt -t 100 -n 1 -m 1000")
	fmt.Println("  ./scan see")
	fmt.Println("  ./scan see -c custom_result.json")
}

func main() {
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "portscan":
		runPortScan(os.Args[2:])
	case "see":
		visualizeResults(os.Args[2:])
	default:
		if !strings.HasPrefix(os.Args[1], "-") {
			fmt.Printf("Unknown command: %s\n", os.Args[1])
		}
		printHelp()
		os.Exit(1)
	}
}

func runPortScan(args []string) {
	// 创建一个新的 FlagSet
	fs := flag.NewFlagSet("portscan", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage of portscan command:")
		fmt.Println("  ./scan portscan [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -i string    Target IP address (single IP mode)")
		fmt.Println("  -r string    File containing IP addresses (file mode, *.txt)")
		fmt.Println("  -t int       Number of threads (default 50)")
		fmt.Println("  -n int       Start port number (default 1)")
		fmt.Println("  -m int       End port number (default 65535)")
		fmt.Println("\nExamples:")
		fmt.Println("  ./scan portscan -i 192.168.1.1")
		fmt.Println("  ./scan portscan -i 192.168.1.1 -t 100 -n 80 -m 443")
		fmt.Println("  ./scan portscan -r ips.txt -t 50")
	}

	var (
		ip        string
		threads   int
		ipFile    string
		startPort int
		endPort   int
	)

	fs.StringVar(&ip, "i", "", "Target IP address")
	fs.IntVar(&threads, "t", 50, "Number of threads")
	fs.StringVar(&ipFile, "r", "", "File containing IP addresses")
	fs.IntVar(&startPort, "n", 1, "Start port number")
	fs.IntVar(&endPort, "m", 65535, "End port number")

	fs.Parse(args)

	// 参数验证
	if (ip == "" && ipFile == "") || (ip != "" && ipFile != "") {
		fmt.Println("Error: Must specify either -i or -r flag, but not both")
		fs.Usage()
		os.Exit(1)
	}

	// 端口范围
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		fmt.Println("Error: Invalid port range")
		os.Exit(1)
	}

	// 线程数限制
	//if threads > 100 {
	//	fmt.Println("Warning: Thread count exceeds maximum, setting to 100")
	//	threads = 100
	//}

	// 初始化结果存储
	store := NewResultStore("result.json")
	if err := store.Load(); err != nil {
		fmt.Printf("Error loading existing results: %v\n", err)
		os.Exit(1)
	}

	var ips []string
	if ip != "" {
		if net.ParseIP(ip) == nil {
			fmt.Printf("Error: Invalid IP address: %s\n", ip)
			os.Exit(1)
		}
		ips = append(ips, ip)
	} else {
		ips = readIPsFromFile(ipFile)
	}

	fmt.Printf("Starting scan with %d threads\n", threads)
	fmt.Printf("Port range: %d-%d\n", startPort, endPort)
	fmt.Printf("Total IPs to scan: %d\n", len(ips))

	for _, targetIP := range ips {
		fmt.Printf("Scanning IP: %s\n", targetIP)
		scanPorts(targetIP, startPort, endPort, threads, store)
	}

	fmt.Println("Scan completed. Results stored in result.json")
}

func visualizeResults(args []string) {
	fs := flag.NewFlagSet("see", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage of see command:")
		fmt.Println("  ./scan see [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -c string        Specify the result file to visualize (default \"result.json\")")
		fmt.Println("  --output-web     Export all web services to web_services.txt")
		fmt.Println("  --output-html    Export results to HTML format")
		fmt.Println("  --use            Use interactive mode")
		fmt.Println("\nExamples:")
		fmt.Println("  ./scan see")
		fmt.Println("  ./scan see -c custom_result.json")
		fmt.Println("  ./scan see --output-web")
		fmt.Println("  ./scan see --output-html")
		fmt.Println("  ./scan see --use")
	}

	var (
		resultFile     string
		outputWeb      bool
		outputHTML     bool
		useInteractive bool
	)
	fs.StringVar(&resultFile, "c", "result.json", "Result file to visualize")
	fs.BoolVar(&outputWeb, "output-web", false, "Export web services")
	fs.BoolVar(&outputHTML, "output-html", false, "Export results to HTML")
	fs.BoolVar(&useInteractive, "use", false, "Use interactive mode")
	fs.Parse(args)

	// 加载结果文件
	store := NewResultStore(resultFile)
	if err := store.Load(); err != nil {
		fmt.Printf("Error loading results file: %v\n", err)
		os.Exit(1)
	}

	if outputWeb {
		exportWebServices(store.results)
		return
	}

	if outputHTML {
		exportHTML(store.results)
		return
	}

	if useInteractive {
		interactiveView(store.results)
		return
	}

	// 默认显示模式
	displayResults(store.results)
}

func interactiveView(results []ScanResult) {
	// 按IP分组
	ipMap := make(map[string][]ScanResult)
	for _, result := range results {
		ipMap[result.IP] = append(ipMap[result.IP], result)
	}

	for {
		// 创建IP列表
		var ips []string
		for ip := range ipMap {
			ips = append(ips, ip)
		}

		// 添加退出选项
		ips = append(ips, "Exit")

		prompt := promptui.Select{
			Label: "Select IP to view details (Press Ctrl+C to quit)",
			Items: ips,
			Size:  10,
		}

		_, selected, err := prompt.Run()
		if err != nil {
			if err == promptui.ErrInterrupt || err == promptui.ErrAbort {
				fmt.Println("\nExiting...")
				return
			}
			fmt.Printf("Prompt failed: %v\n", err)
			return
		}

		if selected == "Exit" {
			return
		}

		// 显示选中IP的详细信息
		clearScreen()
		displayIPDetails(selected, ipMap[selected])

		fmt.Println("\nPress Enter to go back to IP list, Ctrl+C to exit...")
		reader := bufio.NewReader(os.Stdin)
		_, err = reader.ReadString('\n')
		if err != nil {
			fmt.Println("\nExiting...")
			return
		}
		clearScreen()
	}
}

func displayIPDetails(ip string, results []ScanResult) {
	fmt.Printf("=== Details for IP: %s ===\n", ip)
	fmt.Printf("Total ports: %d\n", len(results))
	fmt.Println("Port   Status     Service")
	fmt.Println("----   ------     -------")
	for _, result := range results {
		state, service := parseNmapResult(result.Finger)
		fmt.Printf("%-6d %-10s %s\n", result.Port, state, service)
	}
	fmt.Println("-------------------")
}

func displayResults(results []ScanResult) {
	ipMap := make(map[string][]ScanResult)
	for _, result := range results {
		ipMap[result.IP] = append(ipMap[result.IP], result)
	}

	fmt.Println("\n=== Scan Results ===")
	fmt.Printf("Total IPs scanned: %d\n", len(ipMap))
	fmt.Println("-------------------")

	for ip, results := range ipMap {
		fmt.Printf("\nIP: %s\n", ip)
		fmt.Printf("发现端口: %d\n", len(results))
		fmt.Println("Port   Status     Service")
		fmt.Println("----   ------     -------")
		for _, result := range results {
			state, service := parseNmapResult(result.Finger)
			fmt.Printf("%-6d %-10s %s\n", result.Port, state, service)
		}
		fmt.Println("-------------------")
	}
}

func isWebService(finger string) bool {
	finger = strings.ToLower(finger)
	webKeywords := []string{
		"http",
		"https",
		"nginx",
		"apache",
		"iis",
		"weblogic",
		"tomcat",
		"web server",
		"php",
		"django",
		"flask",
	}

	for _, keyword := range webKeywords {
		if strings.Contains(finger, keyword) {
			return true
		}
	}
	return false
}

func clearScreen() {
	cmd := exec.Command("clear")
	if os.Getenv("OS") == "Windows_NT" {
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func exportWebServices(results []ScanResult) {
	webServices := make([]ScanResult, 0)
	for _, result := range results {
		if isWebService(result.Finger) {
			webServices = append(webServices, result)
		}
	}

	if len(webServices) == 0 {
		fmt.Println("No web services found.")
		return
	}

	// 创建输出文件
	file, err := os.Create("web_services.txt")
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	// 直接写入IP:port格式
	for _, service := range webServices {
		fmt.Fprintf(file, "%s:%d\n", service.IP, service.Port)
	}

	fmt.Printf("Found %d web services, exported to web_services.txt\n", len(webServices))
}

func readIPsFromFile(filename string) []string {
	if !strings.HasSuffix(filename, ".txt") {
		fmt.Println("Error: IP file must be a .txt file")
		os.Exit(1)
	}

	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	uniqueIPs := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			if net.ParseIP(ip) != nil {
				uniqueIPs[ip] = true
			} else {
				fmt.Printf("Warning: Invalid IP address found in file: %s\n", ip)
			}
		}
	}

	if len(uniqueIPs) == 0 {
		fmt.Println("Error: No valid IP addresses found in file")
		os.Exit(1)
	}

	var ips []string
	for ip := range uniqueIPs {
		ips = append(ips, ip)
	}
	return ips
}

func scanPorts(ip string, startPort, endPort, threads int, store *ResultStore) {
	var wg sync.WaitGroup
	var resultWg sync.WaitGroup // 等待结果处理
	portChan := make(chan int, threads)
	resultChan := make(chan ScanResult, threads)

	// 启动工作线程
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if isPortOpen(ip, port) {
					resultChan <- ScanResult{
						IP:       ip,
						Port:     port,
						ScanTime: time.Now(),
					}
					fmt.Printf("Found open port %d on %s\n", port, ip)
				}
			}
		}()
	}

	// 启动结果处理线程
	resultWg.Add(1) // 添加结果处理的等待
	go func() {
		defer resultWg.Done()
		for result := range resultChan {
			// 执行nmap扫描
			result.Finger = nmapScan(result.IP, result.Port)
			if err := store.Add(result); err != nil {
				fmt.Printf("Error saving result: %v\n", err)
			}
		}
	}()

	// 分发端口
	for port := startPort; port <= endPort; port++ {
		portChan <- port
	}
	close(portChan)

	// 等待所有端口扫描完成
	wg.Wait()
	close(resultChan)

	// 等待结果处理完成
	resultWg.Wait()
}

func isPortOpen(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func nmapScan(ip string, port int) string {
	cmd := exec.Command("nmap", "-Pn", "-sV", "-T4",
		fmt.Sprintf("-p%d", port), ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running nmap for %s:%d: %v\n", ip, port, err)
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("%d/tcp", port)) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func parseNmapResult(nmapOutput string) (state, service string) {
	if nmapOutput == "" {
		return "unknown", "unknown"
	}

	// "80/tcp open http Apache httpd 2.4.41"
	parts := strings.Fields(nmapOutput)
	if len(parts) < 3 {
		return "unknown", "unknown"
	}

	// 获取端口状态（通常是第二个字段）
	state = parts[1]

	// 获取服务信息（第三个字段及之后）
	if len(parts) > 3 {
		service = strings.Join(parts[3:], " ")
	} else if len(parts) == 3 {
		service = parts[2]
	} else {
		service = "unknown"
	}

	return state, service
}

// 导出html功能

func exportHTML(results []ScanResult) {
	// 按IP分组
	ipMap := make(map[string][]ScanResult)
	for _, result := range results {
		ipMap[result.IP] = append(ipMap[result.IP], result)
	}

	// 创建HTML文件
	file, err := os.Create("scan_results.html")
	if err != nil {
		fmt.Printf("Error creating HTML file: %v\n", err)
		return
	}
	defer file.Close()

	// HTML头部
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .ip-card {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .ip-header {
            background-color: #3498db;
            color: white;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .web-service {
            color: #27ae60;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Port Scan Results</h1>
            <p>Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
            <p>Total IPs scanned: ` + fmt.Sprintf("%d", len(ipMap)) + `</p>
        </div>`

	// IP信息
	for ip, services := range ipMap {
		html += fmt.Sprintf(`
        <div class="ip-card">
            <div class="ip-header">
                <h2>IP: %s</h2>
                <p>Open ports: %d</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Scan Time</th>
                    </tr>
                </thead>
                <tbody>`, ip, len(services))

		// 添加每个端口的信息
		for _, service := range services {
			state, serviceInfo := parseNmapResult(service.Finger)
			serviceClass := ""
			if isWebService(service.Finger) {
				serviceClass = "web-service"
			}
			html += fmt.Sprintf(`
                    <tr>
                        <td>%d</td>
                        <td>%s</td>
                        <td class="%s">%s</td>
                        <td>%s</td>
                    </tr>`,
				service.Port, state, serviceClass, serviceInfo,
				service.ScanTime.Format("2006-01-02 15:04:05"))
		}

		html += `
                </tbody>
            </table>
        </div>`
	}

	// HTML结尾
	html += `
    </div>
</body>
</html>`

	// 写入文件
	_, err = file.WriteString(html)
	if err != nil {
		fmt.Printf("Error writing HTML file: %v\n", err)
		return
	}

	fmt.Println("Results exported to scan_results.html")
}
