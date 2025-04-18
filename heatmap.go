package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ANSII
const (
	CYAN    = "\033[36m"
	GREEN   = "\033[32m"
	YELLOW  = "\033[33m"
	MAGENTA = "\033[35m"
	RESET   = "\033[0m"
)

func main() {
	// Help
	filePath := flag.String("pcap", "", "Path to the pcap file")
	filterDestIP := flag.String("destip", "", "Filter by destination IP")
	exportFile := flag.String("export", "", "Export result as JSON to the given file")
	flag.Parse()

	if *filePath == "" {
		log.Fatal("Please provide a path to a pcap file using the -pcap flag.")
	}

	handle, err := pcap.OpenOffline(*filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Extracted information
	sourceIPs := make(map[string]int)
	sourcePorts := make(map[int]int)
	packetSizes := make(map[int]int)
	ttls := make(map[uint8]int)
	destinationIPs := make(map[string]int)
	destinationPorts := make(map[int]int)
	payloads := make(map[string]int)
	tcpFlags := make(map[string]int)
	protocols := make(map[string]int)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		if *filterDestIP != "" && ip.DstIP.String() != *filterDestIP {
			continue
		}

		switch ip.Protocol {
		case layers.IPProtocolTCP:
			protocols["TCP"]++
		case layers.IPProtocolUDP:
			protocols["UDP"]++
		case layers.IPProtocolICMPv4:
			protocols["ICMPv4"]++
		case layers.IPProtocolICMPv6:
			protocols["ICMPv6"]++
		default:
			protocols[ip.Protocol.String()]++
		}

		transportLayer := packet.TransportLayer()
		var srcPort, dstPort int
		if transportLayer != nil {
			switch transport := transportLayer.(type) {
			case *layers.TCP:
				srcPort = int(transport.SrcPort)
				dstPort = int(transport.DstPort)

				flags := ""
				if transport.SYN {
					flags += "SYN,"
				}
				if transport.ACK {
					flags += "ACK,"
				}
				if transport.FIN {
					flags += "FIN,"
				}
				if transport.RST {
					flags += "RST,"
				}
				if transport.PSH {
					flags += "PSH,"
				}
				if transport.URG {
					flags += "URG,"
				}
				if transport.ECE {
					flags += "ECE,"
				}
				if transport.CWR {
					flags += "CWR,"
				}
				if flags != "" {
					flags = flags[:len(flags)-1]
					tcpFlags[flags]++
				}
			case *layers.UDP:
				srcPort = int(transport.SrcPort)
				dstPort = int(transport.DstPort)
			}
		}

		sourceIPs[ip.SrcIP.String()]++
		sourcePorts[srcPort]++
		packetSizes[len(packet.Data())]++
		ttls[ip.TTL]++
		destinationIPs[ip.DstIP.String()]++
		destinationPorts[dstPort]++

		if app := packet.ApplicationLayer(); app != nil {
			data := app.Payload()
			if len(data) > 0 {
				truncated := data
				if len(data) > 32 {
					truncated = data[:32]
				}
				payloadHex := hex.EncodeToString(truncated)
				payloads[payloadHex]++
			}
		}
	}

	result := map[string]interface{}{
		"source_ips":        sourceIPs,
		"source_ports":      sourcePorts,
		"packet_sizes":      packetSizes,
		"ttls":              ttls,
		"destination_ips":   destinationIPs,
		"destination_ports": destinationPorts,
		"payloads":          payloads,
		"tcp_flags":         tcpFlags,
		"protocols":         protocols,
	}
	//Json export
	if *exportFile != "" {
		file, err := os.Create(*exportFile)
		if err != nil {
			log.Fatalf("Failed to create export file: %v", err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			log.Fatalf("Failed to write JSON: %v", err)
		}
		fmt.Printf(MAGENTA+"Exported results to %s\n"+RESET, *exportFile)
	}

	printSection("Source IPs Heatmap", sourceIPs)
	printSection("Source Ports Heatmap", sourcePorts)
	printSection("Packet Sizes Heatmap", packetSizes)
	printSection("TTL Heatmap", ttls)
	printSection("Destination IPs Heatmap", destinationIPs)
	printSection("Destination Ports Heatmap", destinationPorts)
	printSection("Top Payloads (hex, truncated)", payloads)
	printSection("Top TCP Flags", tcpFlags)
	printSection("Top Protocols", protocols)
}

func printSection(title string, data interface{}) {
	fmt.Printf("\n%s%s:%s\n", CYAN, title, RESET)
	printTopHeatmap(data)
}

func printTopHeatmap(data interface{}) {
	var sortedData []struct {
		Key   interface{}
		Value int
	}

	switch data := data.(type) {
	case map[string]int:
		for key, value := range data {
			sortedData = append(sortedData, struct {
				Key   interface{}
				Value int
			}{Key: key, Value: value})
		}
	case map[int]int:
		for key, value := range data {
			sortedData = append(sortedData, struct {
				Key   interface{}
				Value int
			}{Key: key, Value: value})
		}
	case map[uint8]int:
		for key, value := range data {
			sortedData = append(sortedData, struct {
				Key   interface{}
				Value int
			}{Key: key, Value: value})
		}
	default:
		fmt.Println("Unknown data type")
		return
	}

	sort.Slice(sortedData, func(i, j int) bool {
		return sortedData[i].Value > sortedData[j].Value
	})

	top := 10
	if len(sortedData) < top {
		top = len(sortedData)
	}
	for i := 0; i < top; i++ {
		fmt.Printf("%sKey:%s %v %sCount:%s %d\n",
			GREEN, RESET, sortedData[i].Key,
			YELLOW, RESET, sortedData[i].Value)
	}
}
