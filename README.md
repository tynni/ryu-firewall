# SDN Firewall with Ryu

An adaptive Software-Defined Networking (SDN) firewall built using the **Ryu controller** and tested in **Mininet**.  
This project demonstrates how SDN programmability can detect abnormal traffic and dynamically install blocking rules in real time.

## 🧠 Project Purpose

Traditional firewalls rely on static rules and are hard to update during attacks.  
Our goal is to build a **dynamic SDN firewall** that:

- Monitors network traffic using OpenFlow statistics  
- Detects abnormal or excessive flows  
- Automatically installs DROP rules to block suspicious sources  
- Compares **Static Firewall** vs **Dynamic Firewall** performance  
- Shows why SDN is powerful for network security and control  

## Project Structure

```
ryu-firewall/
├── dynamic_firewall.py        # Adaptive Ryu firewall (monitors flows + dynamic blocking)
├── static_firewall.py         # Static ACL-based firewall
├── benchmarks.py              # Benchmark suite for the dynamic firewall
├── benchmark_static.py        # Benchmark suite for the static firewall
├── README.md                  # Documentation
```

## How to Run this Project

### **1. Clone inside your Mininet VM**
```bash
git clone https://github.com/tynni/ryu-firewall.git
cd ryu-firewall
```
### **2. Run a Ryu controller**
```bash
ryu-manager controller/dynamic_firewall.py
or 
ryu-manager controller/static_firewall.py
```

### **3. Start Tests**
```bash
sudo python3 tests/benchmarks.py
sudo python3 test/benchmark_static.py
```

### **4. Display Results**
```bash
cat benchmark_results.cvs
cat benchmark_static_results.cvs
```