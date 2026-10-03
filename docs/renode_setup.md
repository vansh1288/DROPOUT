# Renode Multi-MCU Emulation Setup

**Branch:** `feature/member-3-embedded`  
**Target:** NUCLEO-F446RE (STM32F446RE, Cortex-M4F @ 180 MHz)  
**Date:** 2026-10-03

---

## Overview

This document describes the Renode emulation environment for testing the federated learning protocol with multiple virtual NUCLEO-F446RE MCUs, including network impairment simulation and dropout/recovery scenarios.

---

## Directory Structure

```
emulation/
├── multi_node.resc         # Main multi-node script (3 nodes, basic impairment)
├── dropout_test.resc       # Dropout-specific test script (4 nodes, scenario macros)
├── platforms/
│   └── cpus/
│       └── cortex_m4_nucleo_f446re.repl  # Platform description for NUCLEO-F446RE
```

---

## Prerequisites

### Renode Installation
```bash
# Windows (via Chocolatey)
choco install renode

# Linux
sudo apt-get install renode

# Or download from https://renode.io/downloads/
```

### Firmware Binary
The emulation expects a compiled firmware at:
```
C:\DROP\build\cortex_m4\firmware.elf
```

Build with PlatformIO:
```bash
cd C:\DROP
pio run -e cortex_m4
```

---

## Platform Description: `cortex_m4_nucleo_f446re.repl`

### Peripherals Configured
| Peripheral | Instance | Address | Notes |
|------------|----------|---------|-------|
| CPU | CortexM4F | - | 180 MHz, FPU |
| Flash | 512 KB | 0x08000000 | 16 KB pages |
| SRAM1 | 128 KB | 0x20000000 | Main RAM |
| SRAM2 | 128 KB | 0x20020000 | Additional RAM |
| GPIO A-H | 16 pins each | 0x40020000+ | All ports |
| USART1-6 | 6 UARTs | 0x40004400+ | USART2 = virtual console |
| DMA1/2 | 8 channels each | 0x40026000+ | UART RX/TX |
| NVIC | 96 IRQs | 0xE000E100 | 4 priority bits |
| SysTick | 1 MHz | - | 1 ms tick |
| EXTI | 23 lines | 0x40013C00 | GPIO interrupts |
| RCC | - | 0x40023800 | HSE 8 MHz, HSI 16 MHz |

### Pin Mapping (Virtual)
| Pin | Function | Connected To |
|-----|----------|--------------|
| PA2 | USART2_TX | Virtual Switch |
| PA3 | USART2_RX | Virtual Switch |
| PA9 | USART1_TX | (unused) |
| PA10 | USART1_RX | (unused) |
| PB0 | LED1 (Green) | GPIO |
| PB7 | LED2 (Blue) | GPIO |
| PB14 | LED3 (Red) | GPIO |
| PC13 | USER_BUTTON | GPIO |

---

## Running the Emulation

### Basic Multi-Node (3 nodes)
```bash
renode emulation/multi_node.resc
```

### Dropout Test (4 nodes with scenario macros)
```bash
renode emulation/dropout_test.resc
```

### Interactive Commands
Once in Renode monitor:
```renode
# Start all nodes
start_all

# Pause all nodes
pause_all

# Reset all nodes
reset_all

# Set network impairment (loss=5%, latency=50ms)
configure_impairment 0.05 50

# Simulate dropout of node 2
dropout_node 2

# Recover node 2
recover_node 2

# Run full dropout scenario
run_dropout_scenario

# Run protocol test with dropout/recovery
run_protocol_test

# Run loss sweep (0/1/5/10%)
run_loss_sweep

# Run latency sweep (0/20/50/100ms)
run_latency_sweep

# Run combined sweep
run_combined_sweep
```

---

## Network Impairment Configuration

### Parameters
| Parameter | Range | Default | Description |
|-----------|-------|---------|-------------|
| Loss Rate | 0.0 - 1.0 | 0.0 | Packet drop probability |
| Latency | 0 - 1000 ms | 0 | One-way latency per packet |

### Test Matrix
| Test | Loss Rate | Latency | Description |
|------|-----------|---------|-------------|
| Baseline | 0% | 0 ms | Ideal network |
| Low Loss | 1% | 0 ms | Light packet loss |
| Medium Loss | 5% | 0 ms | Moderate packet loss |
| High Loss | 10% | 0 ms | Heavy packet loss |
| Low Latency | 0% | 20 ms | Small delay |
| Medium Latency | 0% | 50 ms | Moderate delay |
| High Latency | 0% | 100 ms | Large delay |
| Combined 1 | 1% | 20 ms | Realistic edge |
| Combined 2 | 5% | 50 ms | Challenging |
| Combined 3 | 10% | 100 ms | Stress test |

---

## Dropout/Recovery Scenario

### Protocol Flow Tested
```
Round 1: Normal operation (all 4 nodes)
  ↓
Round 2: Network degradation (1% loss, 20ms latency)
  ↓
Round 3: Node 2 drops out (50% loss, 100ms latency → pause + disconnect)
  ↓ Other nodes detect dropout, initiate Shamir recovery
Round 4: Recovery - Node 2 rejoins (0% loss, 0ms latency → connect + start)
  ↓ Node 2 receives recovered mask, resumes participation
Round 5: Post-recovery validation (all nodes healthy)
```

### Macros for Manual Control
```renode
# Simulate dropout with custom impairment
simulate_dropout 2 0.5 100

# Simulate recovery
simulate_recovery 2

# Set global network conditions
set_network_conditions 0.05 50
```

---

## Monitoring & Debugging

### Per-Node Console Access
```renode
# Switch to node0 console
emulation node0

# View CPU state
cpu0.PrintCPUInfo()

# Check UART output
node0.Sysbus.usart2.LogFilePath = "node0_uart.log"

# Monitor GPIO
node0.Sysbus.gpiob.Pin9.Get()
```

### Logging
```renode
# Enable UART logging for all nodes
for $i in 0..3
    $node_name = sprintf("node%d", $i)
    emu $node_name.Sysbus.usart2.LogFilePath = sprintf("logs/%s_uart.log", $node_name)
end

# Enable network logging
$switch.LogFilePath = "logs/switch.log"
```

### Performance Counters
```renode
# Get cycle count (requires DWT)
node0.CPU.GetPerformanceCounter()

# Check memory
node0.Machine.GetMemoryMap()
```

---

## Expected Test Outcomes

### Success Criteria
| Metric | Threshold |
|--------|-----------|
| Round completion (baseline) | < 2.5 s |
| Round completion (5% loss) | < 3.5 s |
| Round completion (10% loss) | < 5.0 s |
| Dropout detection time | < 2 s |
| Shamir recovery (t=3) | < 500 ms |
| Post-recovery sync | < 1 round |
| Model consistency (post-recovery) | 100% match |

### Key Log Patterns
```
# Dropout detected
[WARN] node1: Peer node2 missed 3 consecutive chunks

# Recovery initiated
[INFO] node0: Initiating Shamir recovery for client 2 (threshold=3)

# Shares received
[INFO] node1: Submitted Shamir share 1 for client 2
[INFO] node3: Submitted Shamir share 2 for client 2
[INFO] node0: Submitted Shamir share 3 for client 2

# Reconstruction complete
[INFO] node0: Shamir secret reconstructed for client 2

# Recovery complete
[INFO] node2: Mask recovered, resuming round 4
```

---

## Troubleshooting

### Firmware Not Found
```
Error: Could not load binary
```
**Fix:** Build firmware first: `pio run -e cortex_m4`

### Platform Not Found
```
Error: Could not load platform description
```
**Fix:** Ensure `emulation/platforms/cpus/cortex_m4_nucleo_f446re.repl` exists

### Nodes Don't Communicate
```
No packets received between nodes
```
**Fix:** Check switch connections: `$switch.Connect(nodeX.Sysbus.usart2)`

### Impairment Not Applied
```
Loss/latency settings have no effect
```
**Fix:** Verify impairment is enabled: `$imp.Enable()` and check `$imp.LossRate`

### Simulation Too Slow
```
Real-time factor < 0.1x
```
**Fix:** Increase quantum: `emulator SetGlobalQuantum "500000"`

---

## Extending the Setup

### Adding More Nodes
```renode
$num_nodes = 10  # Change in script
# or pass as parameter
```

### Custom Impairment Profiles
```renode
macro burst_loss($duration_ms)
    set_network_conditions(0.5, 0)
    sleep $duration_ms
    set_network_conditions(0.0, 0)
end
```

### Adding SPI/I2C Sensors
Edit `cortex_m4_nucleo_f446re.repl`:
```renode
spi1 = spi.Create("spi1")
sysbus0.Register spi1 at 0x40013000 "SPI1"
# Connect to virtual sensor model
```

---

## CI/CD Integration

### Headless Test Run
```bash
renode --console --disable-xwt -e "include @emulation/dropout_test.resc; run_protocol_test; quit" 2>&1 | tee renode_test.log
```

### Exit Codes
- Renode returns 0 on clean quit
- Use `machine.ExitCode` in scripts for test pass/fail

---

## References

- [Renode Documentation](https://renode.io/docs/latest/)
- [STM32F446RE Reference Manual](https://www.st.com/resource/en/reference_manual/rm0390.pdf)
- [NUCLEO-F446RE User Manual](https://www.st.com/resource/en/user_manual/um1974.pdf)
- Project protocol spec: `docs/protocol.md`

---

*Generated for Member 3 embedded testing. Do not commit emulation artifacts.*