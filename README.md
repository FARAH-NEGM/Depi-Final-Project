
🧠 Project Title

Cyber Control Tower (CCT) – AI-Driven Cybersecurity Simulation & SOC Visualization Platform

📌 Project Overview

Cyber Control Tower (CCT) is a web-based cybersecurity simulation platform that mimics a real Security Operations Center (SOC).
The system transforms raw security logs into structured insights, correlates events into attack stories, maps them to the MITRE ATT&CK framework, and visualizes the organization as a Cyber Digital Twin.

The platform also evaluates human behavior using Trust Scores and measures system efficiency using MTTD and MTTR.

🎯 Key Features
Log ingestion from multiple sources (Windows / Linux / authentication logs)
Event correlation into meaningful security incidents
Attack classification using MITRE ATT&CK framework
Cyber Digital Twin (graph-based visualization of the organization)
Human Trust Score for behavior-based risk analysis
Attack propagation simulation
Incident detection and response recommendations
Performance metrics (MTTD & MTTR)
Interactive dashboard for real-time monitoring
🏗️ System Architecture

The system follows a layered architecture:

Data Ingestion Layer
Cyber Digital Twin (Graph Layer)
Correlation Engine
MITRE Mapping Layer
Trust Score Engine
Attack Propagation Engine
Detection Engine
Response Engine
Metrics Layer (MTTD / MTTR)
Visualization Dashboard
🧩 Project Modules
1. Data Layer
Collects and structures raw logs into JSON format
2. Backend System
Handles ingestion, correlation, MITRE mapping, and scoring
3. Graph Engine
Builds Cyber Digital Twin representation of the organization
4. Frontend Dashboard
Displays incidents, analytics, and live graph visualization
5. Metrics Engine
Calculates system performance (MTTD / MTTR)
📊 Technologies Used
Frontend: HTML, CSS, JavaScript (or React optional)
Backend: Node.js / Python
Data Format: JSON
Visualization: D3.js / Cytoscape.js (for graph)
📈 Key Concepts
Security Operations Center (SOC) simulation
Behavioral analysis and Trust Scoring
Attack correlation and incident generation
MITRE ATT&CK mapping
Graph-based cybersecurity modeling
👥 Team Roles
Data Collection & Dataset Preparation
Backend Development (Ingestion + APIs)
Correlation & MITRE Mapping
Trust Score & Metrics Engine
Frontend Dashboard
Cyber Digital Twin Visualization
⚙️ System Workflow
Logs are collected from multiple sources
Data is structured into events
Events are correlated into incidents
Incidents are mapped to MITRE ATT&CK
User behavior is analyzed (Trust Score)
Attacks are simulated and propagated
Dashboard visualizes results
Performance metrics are calculated
📌 Performance Metrics
MTTD (Mean Time to Detect): Time taken to detect an attack
MTTR (Mean Time to Respond): Time taken to respond and mitigate
🚀 Project Goal

To move beyond traditional SIEM systems by introducing:

Behavioral analysis
Attack storytelling instead of isolated logs
Real-time cyber visualization (Digital Twin)
Human risk evaluation alongside system risk
📷 Future Improvements
Real-time integration with live SIEM tools
Machine learning-based anomaly detection
Advanced automation for response actions
Cloud deployment
📚 References
MITRE ATT&CK Framework
SOC and SIEM concepts
Cyber threat modeling and graph analytics
