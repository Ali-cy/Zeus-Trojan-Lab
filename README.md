# Zeus-Trojan-Lab
Table of Contents

- Overview
- Tools Used
- Project Setup
- Analysis Steps
- Findings
- YARA Rule
- Conclusion
- License

Overview
This project aims to analyze the Zeus Banking Trojan, a notorious piece of malware known for stealing financial information. The analysis involves setting up a secure environment, performing static and dynamic analysis, and documenting the findings.
Tools Used

- VirusTotal: For scanning and identifying the Trojan using multiple antivirus engines.
- PE Studio: For static analysis and identifying suspicious strings and imports.
- Floss: For extracting strings from the executable.
- Capa: For detecting the capabilities of the malware and mapping them to the MITRE ATT&CK framework.
- Cutter: For reverse engineering and viewing the assembly-level instructions.
- Process Monitor (Procmon): For monitoring real-time file system, registry, and process/thread activity.
- Wireshark: For capturing and analyzing network traffic.
- YARA: For creating detection rules based on unique signatures found in the malware.

Project Setup

1. Set up an isolated malware analysis lab:
    - Use VirtualBox with two virtual machines: one for analysis (Flare VM) and one for simulating network services (Remnux).
    - Alternatively, set up a cloud-based lab using AWS.
2. Prepare the environment:
    - Ensure internet connectivity for downloading necessary tools and malware samples.
    - Take snapshots of the virtual machines to revert to a clean state if needed.

Analysis Steps

1. Static Analysis:
    - Use PE Studio to calculate hashes, identify imports, and extract strings.
    - Use Floss to deobfuscate and extract additional strings.
    - Use Capa to identify the capabilities of the malware.
2. Advanced Static Analysis:
    - Use Cutter to reverse engineer the binary and view assembly instructions.
    - Identify key functions and potential obfuscation techniques.
3. Dynamic Analysis:
    - Use Process Monitor to capture real-time activity on the system.
    - Identify process creation, file system changes, and registry modifications.
    - Use Wireshark to capture network traffic and identify any command-and-control (C2) communications.
4. Indicator of Compromise (IOC) Creation:
    - Create YARA rules to detect the Zeus Trojan based on unique strings and patterns identified during analysis.

Findings

- VirusTotal Output: The Zeus Trojan sample was flagged as malicious by multiple antivirus engines.
- Hashes: The calculated hashes (MD5, SHA-1, SHA-256) uniquely identify the sample.
- Static Analysis:
    - Identified suspicious strings and API calls used by the malware.
    - Found potential obfuscation techniques in the function names.
- Dynamic Analysis:
    - Observed process creation and deletion, indicating self-deletion and persistence mechanisms.
    - Detected network traffic to suspicious domains.
- YARA Rule: A custom YARA rule was created to detect the Zeus Trojan based on the findings.

Conclusion
The analysis of the Zeus Banking Trojan provided insights into its behavior, including its static and dynamic characteristics. The findings and the created YARA rule can help in detecting and mitigating this malware in real-world environments.

