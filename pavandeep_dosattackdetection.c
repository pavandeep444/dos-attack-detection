#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <ctime>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include <iomanip>

// Parameters
const int THRESHOLD = 100;           // Packets per second to consider DoS
const int MONITOR_DURATION = 10;     // Monitor traffic for 10 seconds
const char* LOG_FILE = "/var/log/dos_alerts_cpp_extended.log";  // DoS Log file
const char* TRAFFIC_LOG_FILE = "/var/log/traffic_analysis.log";  // Traffic analysis log file

// Struct to store packet details
struct PacketDetails {
    std::string srcIP;
    std::string destIP;
    int packetSize;
    std::string protocol;
    std::string timestamp;
};

// Struct to store attack details
struct AttackDetails {
    std::string ip;
    int packetCount;
    std::string timestamp;
    std::string riskLevel;
};

// Global data structures
std::unordered_map<std::string, int> ipPacketCount; // Count packets per IP
std::vector<PacketDetails> packetLog;               // Log of all packets
std::mutex packetMutex;                             // Mutex for synchronization

// Function to get current timestamp
std::string getCurrentTime() {
    time_t now = time(0);
    char* dt = ctime(&now);
    return std::string(dt).substr(0, 24);  // Remove newline from ctime
}

// Function to log DoS attack details
void logDoSAttack(const AttackDetails& attack) {
    std::ofstream logFile(LOG_FILE, std::ios::app);
    if (!logFile) {
        std::cerr << "Error opening DoS log file!" << std::endl;
        return;
    }
    logFile << "************ DoS Attack Detected ************" << std::endl;
    logFile << "Time: " << attack.timestamp << std::endl;
    logFile << "Attacker IP: " << attack.ip << std::endl;
    logFile << "Packets: " << attack.packetCount << std::endl;
    logFile << "Risk Level: " << attack.riskLevel << std::endl;
    logFile << "*" << std::endl;
    logFile.close();
    std::cout << "DoS alert logged for IP: " << attack.ip << std::endl;
}

// Function to classify attack risk based on packet count
std::string classifyRisk(int packetCount) {
    if (packetCount > 500) {
        return "High";
    } else if (packetCount > 200) {
        return "Medium";
    }
    return "Low";
}

// Function to log packet details into a traffic analysis file
void logTrafficAnalysis() {
    std::ofstream trafficLogFile(TRAFFIC_LOG_FILE, std::ios::app);
    if (!trafficLogFile) {
        std::cerr << "Error opening traffic log file!" << std::endl;
        return;
    }

    for (const auto& packet : packetLog) {
        trafficLogFile << "Time: " << packet.timestamp << std::endl;
        trafficLogFile << "Source IP: " << packet.srcIP << std::endl;
        trafficLogFile << "Destination IP: " << packet.destIP << std::endl;
        trafficLogFile << "Packet Size: " << packet.packetSize << " bytes" << std::endl;
        trafficLogFile << "Protocol: " << packet.protocol << std::endl;
        trafficLogFile << "-------------------------------------------" << std::endl;
    }

    trafficLogFile.close();
}

// Function to store general packet details
void logPacketDetails(const PacketDetails& packet) {
    packetLog.push_back(packet);
}

// Function to display traffic statistics
void displayTrafficStatistics() {
    std::lock_guard<std::mutex> lock(packetMutex);
    std::cout << "==================== Traffic Summary ====================" << std::endl;
    std::cout << "Source IP          | Destination IP   | Size (bytes) | Protocol   | Time" << std::endl;
    std::cout << "---------------------------------------------------------" << std::endl;
    for (const auto& packet : packetLog) {
        std::cout << std::setw(18) << packet.srcIP
                  << std::setw(18) << packet.destIP
                  << std::setw(12) << packet.packetSize
                  << std::setw(12) << packet.protocol
                  << " | " << packet.timestamp << std::endl;
    }
    std::cout << "=========================================================" << std::endl;

    // After displaying traffic statistics, log them to a file
    logTrafficAnalysis();
    packetLog.clear();  // Clear packet log for next monitoring cycle
}

// Packet handler for processing each packet
void packetHandler(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip* iph = (struct ip*)(packet + 14);  // Skip Ethernet header
    int packetSize = header->len;
    
    // Extract source and destination IPs
    std::string srcIP = inet_ntoa(iph->ip_src);
    std::string destIP = inet_ntoa(iph->ip_dst);

    // Determine protocol
    std::string protocol;
    if (iph->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
    } else if (iph->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
    } else {
        protocol = "Other";
    }

    // Get the current timestamp
    std::string timestamp = getCurrentTime();

    // Store packet details
    PacketDetails packetDetails = { srcIP, destIP, packetSize, protocol, timestamp };

    {
        std::lock_guard<std::mutex> lock(packetMutex);
        ipPacketCount[srcIP]++;
        logPacketDetails(packetDetails);  // Log packet
    }
}

// Analyze traffic for DoS attacks
void analyzeTraffic() {
    std::lock_guard<std::mutex> lock(packetMutex);
    for (const auto& entry : ipPacketCount) {
        if (entry.second > THRESHOLD) {
            // Detected potential DoS attack
            AttackDetails attack;
            attack.ip = entry.first;
            attack.packetCount = entry.second;
            attack.timestamp = getCurrentTime();
            attack.riskLevel = classifyRisk(entry.second);
            logDoSAttack(attack);
        }
    }
    ipPacketCount.clear();  // Reset for next cycle
}

// Monitor traffic for a given duration
void monitorTraffic(pcap_t* handle) {
    std::cout << "Monitoring traffic for " << MONITOR_DURATION << " seconds..." << std::endl;
    pcap_loop(handle, 0, packetHandler, NULL);
    std::this_thread::sleep_for(std::chrono::seconds(MONITOR_DURATION));
}

// Setup packet capture
pcap_t* setupPacketCapture(char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        exit(1);
    }
    return handle;
}

// Main detection loop
void runDetection(pcap_t* handle) {
    while (true) {
        std::thread monitorThread(monitorTraffic, handle);
        monitorThread.join();
        analyzeTraffic();
        displayTrafficStatistics();  // Display traffic summary after every analysis
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    char* dev = argv[1];  // Network interface
    pcap_t* handle = setupPacketCapture(dev);

    std::cout << "Starting DoS detection on interface " << dev << std::endl;
    std::cout << "Logs will be saved to " << LOG_FILE << std::endl;

    runDetection(handle);

    pcap_close(handle);
    return 0;
}
