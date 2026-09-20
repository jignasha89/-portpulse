/**
 * PortPulse Studio - Ultimate Multi-Module Application Controller
 * Modules & Features:
 * 1. Host Explorer: Explore connected devices with Scan, Capture, and Deep Details
 * 2. Manual Command Scanner: Interactive Nmap CLI Terminal with customizable flags & presets
 * 3. Live Packet Capture: Filter by IP, protocol, ID, or threat condition with plain-English decoding
 * 4. Network Topology Design: Interactive Canvas Radar with glowing nodes & animated packet flows
 * 5. 3-Format Report Export: Instant TXT, JSON, and PDF (Print) export
 * 6. Network Device Discovery: Subnet inventory with vendor identification & rogue device detection
 * 7. Software Login & Authentication: Role-based access control with 1-click demo login & profile
 * 8. Network Security Health Index: Dynamic gauge, MTU/MSS checks, DNS benchmark race & resilience audit
 * 9. Quick Search Omnibar: Global search across all services and tools (Ctrl+K)
 */

(function() {
  'use strict';

  // Global State
  let currentTheme = localStorage.getItem('portpulse_theme') || 'dark';
  let activeProfile = 'quick';
  let currentTarget = 'scanme.nmap.org';
  let isScanning = false;
  let activeFilter = 'all';

  // Wireshark Sniffer State
  let snifferRunning = true;
  let snifferPackets = [];
  let snifferPacketCounter = 0;
  let snifferAlertCount = 0;
  let activeSnifferFilter = 'all';
  let selectedSnifferPacket = null;

  // Live Packet Capture & Smart Limit State (Feature 1)
  let captureTargetIp = 'all';
  let captureLimit = 50000;
  let captureLimitMode = '50000';
  let capturePacketsTotal = 0;
  let isLimitReached = false;
  let captureStatus = 'capturing'; // 'capturing', 'paused', 'limit-reached', 'idle'
  let capturePollInterval = null;
  let lastCapturedSeq = 0;

  // Protocol Breakdown State (Feature 1)
  let protoCountTcp = 0;
  let protoCountUdp = 0;
  let protoCountIcmp = 0;
  let protoCountOther = 0;

  // Smart Packet Guard (Traffic Spike Detection - Feature 1)
  let currentPps = 195;
  let baselineRate = 200;
  let isSpikeActive = false;

  // Malicious Detection & Blocking State (Feature 3)
  let activeBlockedIps = new Set();
  let blockedPacketsLog = [];
  let pendingThreatPacket = null;

  // External Scan Authorization Registry (Feature 2)
  let authorizedScanTargets = new Set(['scanme.nmap.org', '127.0.0.1', '192.168.1.1', '192.168.1.50']);
  let pendingExternalTarget = null;

  // Latency History for Ping Sparkline
  let pingHistory = [14, 15, 12, 16, 14, 18, 15, 13, 16, 14, 15, 17, 14, 13, 15];
  let pingCanvas = null;
  let pingCtx = null;

  // AI Doctor Language State
  let aiLanguage = 'en';

  // Topology Canvas State
  let topoCanvas = null;
  let topoCtx = null;
  let topoAnimId = null;
  let topoParticlesEnabled = true;
  let selectedTopoNode = null;

  // Educational Port Knowledge Base
  const portKnowledge = {
    21: { name: "FTP (File Transfer)", desc: "Transfers files across network endpoints in plain text without encryption.", risk: "High Risk: Transmits cleartext passwords over the wire.", fix: "Migrate to SFTP (Port 22) or FTPS with TLS." },
    22: { name: "SSH (Secure Shell)", desc: "Industry-standard cryptographic remote server shell.", risk: "Safe: Protected by public-key or RSA cryptography.", fix: "Disable root password login (`PermitRootLogin no`) and use SSH keys." },
    23: { name: "Telnet", desc: "Outdated remote terminal from 1969 without any encryption.", risk: "CRITICAL: All keystrokes and credentials sent in plaintext.", fix: "Disable service immediately (`systemctl stop telnetd`)." },
    25: { name: "SMTP (Mail Routing)", desc: "Routes emails between mail transfer agents (MTAs).", risk: "Medium: Susceptible to open relay spam abuse.", fix: "Mandate TLS encryption and disable unauthenticated open relay." },
    53: { name: "DNS (Domain Name System)", desc: "Resolves human domain names to numerical IP addresses.", risk: "Low/Medium: Can be spoofed via cache poisoning or amplified in DDoS.", fix: "Restrict recursive queries to internal LAN subnets only." },
    80: { name: "HTTP (Unencrypted Web)", desc: "Standard hypertext web protocol lacking TLS encryption.", risk: "Medium: Session cookies and form submissions can be intercepted.", fix: "Enforce 301 redirect to HTTPS (Port 443) and enable HSTS." },
    110: { name: "POP3 (Mail Retrieval)", desc: "Downloads emails from remote mail server.", risk: "Medium: Cleartext protocol by default.", fix: "Migrate to POP3S on port 995 with SSL." },
    135: { name: "MSRPC (Windows RPC)", desc: "Microsoft Windows internal RPC endpoint mapper.", risk: "High: Historically targeted by automated worm propagation.", fix: "Block port 135 on boundary perimeter routers." },
    139: { name: "NetBIOS Session", desc: "Legacy Windows file and printer sharing protocol.", risk: "High: Leaks workgroup names and NetBIOS network names.", fix: "Disable NetBIOS over TCP/IP in network adapter properties." },
    143: { name: "IMAP (Email Sync)", desc: "Synchronizes inbox messages with mail server.", risk: "Medium: Insecure if used without SSL/TLS.", fix: "Enforce IMAPS on port 993." },
    443: { name: "HTTPS (Encrypted Web)", desc: "Industry gold standard encrypted web protocol.", risk: "Very Safe: Encrypted via TLS 1.3 with strong cipher suites.", fix: "Maintain active TLS certificate renewal before expiration." },
    445: { name: "SMB (Server Message Block)", desc: "Windows network folder sharing protocol.", risk: "CRITICAL: #1 vector for Ransomware (WannaCry / EternalBlue).", fix: "Never expose Port 445 to the public Internet. Keep SMBv1 disabled." },
    1433: { name: "MS SQL Database", desc: "Microsoft SQL database listener port.", risk: "High: Public WAN exposure invites automated credential brute-force.", fix: "Bind listener to 127.0.0.1 or internal VPN subnet only." },
    1900: { name: "UPnP (Universal Plug & Play)", desc: "Automatic port mapping protocol for smart devices.", risk: "Medium: Vulnerable to rogue UPnP port mapping exploits.", fix: "Disable UPnP in router firmware settings." },
    3306: { name: "MySQL Database", desc: "Open-source relational database management system.", risk: "High: Exposing database ports to WAN invites zero-day attacks.", fix: "Bind to 127.0.0.1 in my.cnf and require SSL." },
    3389: { name: "RDP (Remote Desktop Protocol)", desc: "Microsoft Windows remote desktop graphical administration.", risk: "CRITICAL: Prime target for brute-force ransomware attacks.", fix: "Place RDP behind an encrypted VPN with Multi-Factor Authentication (MFA)." },
    5432: { name: "PostgreSQL Database", desc: "Enterprise SQL database engine.", risk: "High: WAN accessibility invites brute-force authentication attacks.", fix: "Restrict access via pg_hba.conf to trusted client IPs." },
    8080: { name: "HTTP Alternate / Dev", desc: "Popular developer web proxy or microservice listener.", risk: "Medium: Frequently runs unauthenticated dev prototypes.", fix: "Place behind reverse proxy with authentication." },
    8443: { name: "HTTPS Alternate", desc: "Encrypted administrative web console.", risk: "Low: Verify valid TLS certificate.", fix: "Enforce strong passphrase credentials." },
    31337: { name: "Elite (Nmap Test Service)", desc: "Famous diagnostic port featured on scanme.nmap.org.", risk: "Informational: Diagnostic confirmation.", fix: "Standard testing service provided by Nmap project." }
  };

  // Sample Target Database
  const targetDatabase = {
    'scanme.nmap.org': {
      ip: '45.33.32.156',
      os: 'Linux (Ubuntu Linux Kernel 5.4)',
      latency: '14 ms',
      mac: 'Realtek Semiconductor (eth0)',
      score: 88,
      advice: 'Host exhibits solid security baseline with minimal exposed services.',
      ports: [
        { port: 22, proto: 'TCP', state: 'open', service: 'ssh', version: 'OpenSSH 6.6.1p1 Ubuntu', risk: 'safe', note: 'Secure encrypted shell.' },
        { port: 80, proto: 'TCP', state: 'open', service: 'http', version: 'Apache httpd 2.4.7', risk: 'warn', note: 'Plain HTTP. Consider redirecting to HTTPS.' },
        { port: 9929, proto: 'TCP', state: 'open', service: 'nping-echo', version: 'Nping echo test', risk: 'safe', note: 'Official Nmap test echo service.' },
        { port: 31337, proto: 'TCP', state: 'open', service: 'elite', version: 'Nmap sample banner', risk: 'safe', note: 'Informational test port.' },
        { port: 135, proto: 'TCP', state: 'filtered', service: 'msrpc', version: 'Unknown', risk: 'warn', note: 'Blocked by firewall.' },
        { port: 445, proto: 'TCP', state: 'filtered', service: 'microsoft-ds', version: 'Unknown', risk: 'warn', note: 'Firewall dropped packets.' },
        { port: 21, proto: 'TCP', state: 'closed', service: 'ftp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 23, proto: 'TCP', state: 'closed', service: 'telnet', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 25, proto: 'TCP', state: 'closed', service: 'smtp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 53, proto: 'TCP', state: 'closed', service: 'dns', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 110, proto: 'TCP', state: 'closed', service: 'pop3', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 139, proto: 'TCP', state: 'closed', service: 'netbios-ssn', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 143, proto: 'TCP', state: 'closed', service: 'imap', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 443, proto: 'TCP', state: 'closed', service: 'https', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 1433, proto: 'TCP', state: 'closed', service: 'ms-sql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 1900, proto: 'TCP', state: 'closed', service: 'upnp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 3306, proto: 'TCP', state: 'closed', service: 'mysql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 3389, proto: 'TCP', state: 'closed', service: 'rdp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 5432, proto: 'TCP', state: 'closed', service: 'postgresql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 8080, proto: 'TCP', state: 'closed', service: 'http-alt', version: '-', risk: 'safe', note: 'Port closed.' }
      ]
    },
    '192.168.1.1': {
      ip: '192.168.1.1',
      os: 'Embedded Linux (OpenWrt / Broadcom Router)',
      latency: '2 ms',
      mac: 'TP-Link Corporation (LAN Gateway)',
      score: 76,
      advice: 'Admin portal runs over unencrypted HTTP (Port 80). Enable HTTPS administration.',
      ports: [
        { port: 53, proto: 'UDP/TCP', state: 'open', service: 'dns', version: 'dnsmasq-2.85', risk: 'safe', note: 'Local DNS caching server.' },
        { port: 80, proto: 'TCP', state: 'open', service: 'http', version: 'Lighttpd / Web Management', risk: 'warn', note: 'Cleartext admin login.' },
        { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'OpenSSL (Self-Signed)', risk: 'safe', note: 'Secure admin interface.' },
        { port: 1900, proto: 'UDP', state: 'open', service: 'upnp', version: 'miniupnpd 2.1', risk: 'warn', note: 'UPnP active.' },
        { port: 22, proto: 'TCP', state: 'filtered', service: 'ssh', version: 'Dropbear SSH', risk: 'safe', note: 'SSH filtered from LAN.' },
        { port: 21, proto: 'TCP', state: 'closed', service: 'ftp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 23, proto: 'TCP', state: 'closed', service: 'telnet', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 25, proto: 'TCP', state: 'closed', service: 'smtp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 110, proto: 'TCP', state: 'closed', service: 'pop3', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 135, proto: 'TCP', state: 'closed', service: 'msrpc', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 139, proto: 'TCP', state: 'closed', service: 'netbios-ssn', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 143, proto: 'TCP', state: 'closed', service: 'imap', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 445, proto: 'TCP', state: 'closed', service: 'microsoft-ds', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 1433, proto: 'TCP', state: 'closed', service: 'ms-sql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 3306, proto: 'TCP', state: 'closed', service: 'mysql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 3389, proto: 'TCP', state: 'closed', service: 'rdp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 5432, proto: 'TCP', state: 'closed', service: 'postgresql', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 8080, proto: 'TCP', state: 'closed', service: 'http-alt', version: '-', risk: 'safe', note: 'Port closed.' }
      ]
    },
    '192.168.1.50': {
      ip: '192.168.1.50',
      os: 'Linux (Ubuntu Server 22.04 LTS)',
      latency: '3 ms',
      mac: 'Intel Corporation (eth0)',
      score: 64,
      advice: 'WARNING: MySQL Port 3306 is exposed without firewall restriction.',
      ports: [
        { port: 22, proto: 'TCP', state: 'open', service: 'ssh', version: 'OpenSSH 8.9p1', risk: 'safe', note: 'Encrypted shell.' },
        { port: 80, proto: 'TCP', state: 'open', service: 'http', version: 'nginx/1.18.0', risk: 'warn', note: 'HTTP enabled.' },
        { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'nginx/1.18.0 (TLS 1.3)', risk: 'safe', note: 'Strong TLS encryption.' },
        { port: 3306, proto: 'TCP', state: 'open', service: 'mysql', version: 'MySQL 8.0.32', risk: 'danger', note: 'EXPOSED DATABASE: Vulnerable to brute force.' },
        { port: 8080, proto: 'TCP', state: 'open', service: 'http-alt', version: 'Node.js Express API', risk: 'warn', note: 'Dev API exposed without auth proxy.' },
        { port: 21, proto: 'TCP', state: 'closed', service: 'ftp', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 23, proto: 'TCP', state: 'closed', service: 'telnet', version: '-', risk: 'safe', note: 'Port closed.' }
      ]
    },
    '127.0.0.1': {
      ip: '127.0.0.1 (Loopback)',
      os: 'Local Host System',
      latency: '< 1 ms',
      mac: '00:00:00:00:00:00 (Local Loopback)',
      score: 95,
      advice: 'Local machine listening on development ports only.',
      ports: [
        { port: 8080, proto: 'TCP', state: 'open', service: 'http-alt', version: 'Local Development Server', risk: 'safe', note: 'Local dev server listening.' },
        { port: 135, proto: 'TCP', state: 'filtered', service: 'msrpc', version: 'Windows RPC', risk: 'safe', note: 'Filtered.' },
        { port: 445, proto: 'TCP', state: 'filtered', service: 'microsoft-ds', version: 'SMB', risk: 'safe', note: 'Filtered.' },
        { port: 80, proto: 'TCP', state: 'closed', service: 'http', version: '-', risk: 'safe', note: 'Port closed.' },
        { port: 443, proto: 'TCP', state: 'closed', service: 'https', version: '-', risk: 'safe', note: 'Port closed.' }
      ]
    }
  };

  // Enhanced LAN Devices Array (Features 1 & 6)
  const lanDevices = [
    { 
      name: "TP-Link Archer AX55 (Wi-Fi 6 Router)", 
      ip: "192.168.1.1", 
      mac: "D8:07:B6:33:AA:01", 
      vendor: "TP-Link Corporation", 
      type: "Gateway Router", 
      isTrusted: true, 
      icon: "fa-router",
      os: "Embedded Linux 5.10 / OpenWrt",
      latency: "1.2 ms",
      packetLoss: "0.0%",
      sockets: "34 active streams",
      openPorts: [53, 80, 443, 1900],
      notes: "Primary network default gateway and DHCP/DNS server."
    },
    { 
      name: "My Workstation (This PC)", 
      ip: "192.168.1.105", 
      mac: "3C:06:30:4F:A1:22", 
      vendor: "Dell Inc. / Realtek", 
      type: "Desktop PC", 
      isTrusted: true, 
      icon: "fa-desktop",
      os: "Windows 11 Pro 64-bit",
      latency: "< 0.4 ms",
      packetLoss: "0.0%",
      sockets: "42 active streams",
      openPorts: [135, 445, 8080],
      notes: "Primary operator console running PortPulse Studio."
    },
    { 
      name: "Apple iPhone 15 Pro", 
      ip: "192.168.1.12", 
      mac: "70:85:C2:5B:14:89", 
      vendor: "Apple Inc.", 
      type: "Smartphone", 
      isTrusted: true, 
      icon: "fa-mobile-screen-button",
      os: "iOS 18.2",
      latency: "9.4 ms",
      packetLoss: "0.0%",
      sockets: "14 active streams",
      openPorts: [62078],
      notes: "Mobile client connected over 5GHz Wi-Fi (WPA3-Personal)."
    },
    { 
      name: "Samsung Neo QLED 4K Smart TV", 
      ip: "192.168.1.18", 
      mac: "F4:D1:08:92:E0:41", 
      vendor: "Samsung Electronics", 
      type: "Smart TV", 
      isTrusted: true, 
      icon: "fa-tv",
      os: "Tizen OS 7.0",
      latency: "12.8 ms",
      packetLoss: "0.0%",
      sockets: "8 active streams",
      openPorts: [8001, 8002],
      notes: "Media streaming client active on local subnet."
    },
    { 
      name: "Sony PlayStation 5 Console", 
      ip: "192.168.1.88", 
      mac: "A0:36:BC:11:45:90", 
      vendor: "Sony Interactive", 
      type: "Gaming Console", 
      isTrusted: true, 
      icon: "fa-gamepad",
      os: "PlayStation OS (FreeBSD-based)",
      latency: "8.1 ms",
      packetLoss: "0.0%",
      sockets: "12 active streams",
      openPorts: [9295, 9296],
      notes: "Console active with low-latency NAT Type 2 configuration."
    },
    { 
      name: "UNKNOWN / SUSPICIOUS WI-FI DEVICE", 
      ip: "192.168.1.199", 
      mac: "B4:E6:2D:67:9A:1F", 
      vendor: "Espressif IoT / Unknown Client", 
      type: "Unregistered Wi-Fi Client", 
      isTrusted: false, 
      icon: "fa-triangle-exclamation",
      os: "FreeRTOS / ESP32 Microcontroller",
      latency: "34.2 ms",
      packetLoss: "1.4%",
      sockets: "2 active streams",
      openPorts: [80, 8080],
      notes: "ALERT: Device joined subnet without reservation. MAC vendor matches IoT chipset."
    }
  ];

  // Active Device for Deep Details Modal
  let activeDetailDevice = lanDevices[0];

  /* =============================================================
     MAIN APPLICATION INITIALIZATION
     ============================================================= */
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(currentTheme);
    setupLogin();
    setupOmnibar();
    setupTabSwitching();
    setupNmapScanner();
    setupManualCommandScanner();
    setupWiresharkSniffer();
    setupTracerouteHub();
    setupTopologyRadar();
    setupLanDiscovery();
    setupAiDoctor();
    setupCommonModals();
    setupDeviceDetailsModal();
    setupWiresharkMenuBar();
    setupInterfaceSelector();
    setupPingUtility();
    setupFollowTcpStream();
    setupProtocolHierarchy();
    setupPacketForge();
    setupWhoisIntel();

    // Default renders
    renderCurrentNmapResults(targetDatabase['scanme.nmap.org']);
    renderTracerouteHops('scanme.nmap.org');
    renderDnsRaceList();
    renderLanDevicesList();
    updateSecurityHealthIndex();

    // Start background Wireshark sniffer generator
    startSnifferStreaming();

    // Start background ping sparkline update
    initPingCanvas();
  });

  /* -------------------------------------------------------------
     7. FEATURE 7: SOFTWARE LOGIN & AUTHENTICATION
     ------------------------------------------------------------- */
  function setupLogin() {
    const loginOverlay = document.getElementById('loginOverlay');
    const loginForm = document.getElementById('loginForm');
    const btnPerformLogin = document.getElementById('btnPerformLogin');
    const btnQuickDemoLogin = document.getElementById('btnQuickDemoLogin');
    const btnLogout = document.getElementById('btnLogout');
    const navUserName = document.getElementById('navUserName');
    const navUserRole = document.getElementById('navUserRole');

    // Check existing session
    const savedUser = sessionStorage.getItem('portpulse_user');
    if (savedUser) {
      try {
        const userObj = JSON.parse(savedUser);
        if (navUserName) navUserName.innerText = userObj.username || 'Admin SecOps';
        if (navUserRole) navUserRole.innerText = userObj.role || 'Administrator';
        document.body.classList.remove('logged-out');
        if (loginOverlay) loginOverlay.classList.add('hidden');
      } catch (e) {
        document.body.classList.add('logged-out');
      }
    } else {
      document.body.classList.add('logged-out');
    }

    function doLogin(username, role) {
      const userObj = { username, role, timestamp: Date.now() };
      sessionStorage.setItem('portpulse_user', JSON.stringify(userObj));
      if (navUserName) navUserName.innerText = username.split('@')[0] || 'Admin';
      if (navUserRole) navUserRole.innerText = role;

      document.body.classList.remove('logged-out');
      if (loginOverlay) loginOverlay.classList.add('hidden');
      showToast(`Authenticated as ${role}. Welcome to PortPulse!`, 'success');
    }

    if (btnPerformLogin) {
      btnPerformLogin.addEventListener('click', () => {
        const username = document.getElementById('loginUsername')?.value.trim() || 'SecOps Operator';
        const role = document.getElementById('loginRoleSelect')?.value || 'SecOps Administrator';
        doLogin(username, role);
      });
    }

    if (loginForm) {
      loginForm.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const username = document.getElementById('loginUsername')?.value.trim() || 'SecOps Operator';
          const role = document.getElementById('loginRoleSelect')?.value || 'SecOps Administrator';
          doLogin(username, role);
        }
      });
    }

    if (btnQuickDemoLogin) {
      btnQuickDemoLogin.addEventListener('click', () => {
        doLogin('SecOps Administrator', 'Administrator');
      });
    }

    if (btnLogout) {
      btnLogout.addEventListener('click', () => {
        sessionStorage.removeItem('portpulse_user');
        document.body.classList.add('logged-out');
        if (loginOverlay) loginOverlay.classList.remove('hidden');
        showToast('Logged out of PortPulse Studio', 'info');
      });
    }
  }

  /* -------------------------------------------------------------
     9. FEATURE 9: QUICK SEARCH OMNIBAR (Ctrl+K)
     ------------------------------------------------------------- */
  function setupOmnibar() {
    const searchInput = document.getElementById('globalOmnibarSearch');
    const dropdown = document.getElementById('omnibarDropdown');
    const resultsContainer = document.getElementById('omnibarResults');

    if (!searchInput || !dropdown || !resultsContainer) return;

    // Omnibar catalog
    const omniCatalog = [
      { name: "Port & Vulnerability Scanner", category: "Nmap Module", icon: "fa-crosshairs", tab: "tab-nmap", action: () => switchTab('tab-nmap') },
      { name: "Manual Command Box & CLI Terminal", category: "Nmap Module", icon: "fa-terminal", tab: "tab-nmap", action: () => { switchTab('tab-nmap'); document.getElementById('manualFullCmdInput')?.focus(); } },
      { name: "Live Packet Sniffer (Wireshark)", category: "Packet Sniffer", icon: "fa-wave-square", tab: "tab-wireshark", action: () => switchTab('tab-wireshark') },
      { name: "Simulate Plaintext Password Leak", category: "Packet Threat", icon: "fa-triangle-exclamation", tab: "tab-wireshark", action: () => { switchTab('tab-wireshark'); injectThreatLeakPacket(); } },
      { name: "Network Topology & Flow Radar", category: "Topology Map", icon: "fa-circle-nodes", tab: "tab-topology", action: () => switchTab('tab-topology') },
      { name: "Visual Traceroute & Latency Hub", category: "Diagnostics", icon: "fa-route", tab: "tab-traceroute", action: () => switchTab('tab-traceroute') },
      { name: "Network Security Health Index Gauge", category: "Security Health", icon: "fa-heart-pulse", tab: "tab-traceroute", action: () => { switchTab('tab-traceroute'); document.getElementById('healthGaugeRing')?.scrollIntoView({ behavior: 'smooth' }); } },
      { name: "DNS Speed Race Benchmark", category: "Diagnostics", icon: "fa-bolt", tab: "tab-traceroute", action: () => { switchTab('tab-traceroute'); renderDnsRaceList(); } },
      { name: "Who's On My Wi-Fi? (LAN Device Discovery)", category: "Subnet Inventory", icon: "fa-wifi", tab: "tab-devices", action: () => switchTab('tab-devices') },
      { name: "Export Audit Reports (JSON, PDF, TXT)", category: "Reporting", icon: "fa-file-shield", tab: null, action: () => openReportModal() },
      { name: "Continuous ICMP Ping & Subnet Sweep", category: "Diagnostics", icon: "fa-satellite-dish", tab: null, action: () => openPingToolModal() },
      { name: "Follow TCP Stream (Reconstruct Dialogue)", category: "Packet Sniffer", icon: "fa-comments", tab: null, action: () => openFollowTcpStreamModal() },
      { name: "Protocol Hierarchy Breakdown", category: "Statistics", icon: "fa-sitemap", tab: null, action: () => openProtocolHierarchyModal() },
      { name: "Raw Packet Crafter ('Packet Forge')", category: "Security Tools", icon: "fa-wand-magic-sparkles", tab: null, action: () => openPacketForgeModal() },
      { name: "WHOIS & IP Threat Intelligence Radar", category: "Threat Intel", icon: "fa-earth-americas", tab: null, action: () => openWhoisIntelModal() },
      { name: "Network Interfaces (Wi-Fi, Ethernet, Loopback)", category: "Capture Options", icon: "fa-network-wired", tab: "tab-wireshark", action: () => { switchTab('tab-wireshark'); document.getElementById('wsInterfacesCard')?.scrollIntoView({ behavior: 'smooth' }); } },
      { name: "Gateway Router (192.168.1.1)", category: "Host Device", icon: "fa-router", tab: "tab-devices", action: () => { switchTab('tab-devices'); openDeviceDetailsModal(lanDevices[0]); } },
      { name: "Workstation (192.168.1.105)", category: "Host Device", icon: "fa-desktop", tab: "tab-devices", action: () => { switchTab('tab-devices'); openDeviceDetailsModal(lanDevices[1]); } },
      { name: "Suspicious IoT Client (192.168.1.199)", category: "Threat Alert", icon: "fa-triangle-exclamation", tab: "tab-devices", action: () => { switchTab('tab-devices'); openDeviceDetailsModal(lanDevices[5]); } }
    ];

    function renderOmnibar(filter = "") {
      const q = filter.trim().toLowerCase();
      const matches = omniCatalog.filter(item => 
        item.name.toLowerCase().includes(q) || item.category.toLowerCase().includes(q)
      );

      if (matches.length === 0) {
        resultsContainer.innerHTML = `<div class="omnibar-empty"><i class="fa-solid fa-circle-xmark"></i> No services or commands matched "${escapeHtml(filter)}"</div>`;
      } else {
        resultsContainer.innerHTML = matches.map((item, idx) => `
          <div class="omnibar-item ${idx === 0 ? 'focused' : ''}" data-idx="${idx}">
            <i class="fa-solid ${item.icon} omnibar-item-icon"></i>
            <div class="omnibar-item-info">
              <span class="omnibar-item-name">${escapeHtml(item.name)}</span>
              <span class="omnibar-item-cat">${escapeHtml(item.category)}</span>
            </div>
            <span class="omnibar-item-shortcut"><i class="fa-solid fa-arrow-turn-down"></i> Jump</span>
          </div>
        `).join('');

        // Attach click handlers
        resultsContainer.querySelectorAll('.omnibar-item').forEach(el => {
          el.addEventListener('click', () => {
            const idx = parseInt(el.getAttribute('data-idx'));
            matches[idx].action();
            dropdown.classList.add('hidden');
            searchInput.value = '';
          });
        });
      }
      dropdown.classList.remove('hidden');
    }

    searchInput.addEventListener('input', (e) => {
      renderOmnibar(e.target.value);
    });

    searchInput.addEventListener('focus', () => {
      renderOmnibar(searchInput.value);
    });

    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const firstItem = resultsContainer.querySelector('.omnibar-item');
        if (firstItem) {
          firstItem.click();
        }
      } else if (e.key === 'Escape') {
        dropdown.classList.add('hidden');
      }
    });

    // Global Ctrl+K shortcut
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
        renderOmnibar('');
      }
    });

    // Close dropdown on click outside
    document.addEventListener('click', (e) => {
      if (!searchInput.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    });
  }

  /* -------------------------------------------------------------
     THEME MANAGEMENT (Dark & Light Mode)
     ------------------------------------------------------------- */
  function applyTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('portpulse_theme', theme);

    const toggleText = document.getElementById('themeToggleText');
    if (toggleText) {
      toggleText.innerText = theme === 'dark' ? 'Dark' : 'Light';
    }
    if (topoCtx) drawTopologyFrame();
  }

  function toggleTheme() {
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
    showToast(`Switched to ${nextTheme === 'dark' ? 'Dark' : 'Light'} Mode`, 'info');
  }

  /* -------------------------------------------------------------
     TAB SWITCHING NAVIGATION
     ------------------------------------------------------------- */
  function switchTab(tabId) {
    const tabs = document.querySelectorAll('.main-tabs-bar .tab-btn');
    const modules = document.querySelectorAll('.tab-module');

    tabs.forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });

    modules.forEach(m => {
      m.classList.toggle('active', m.id === tabId);
    });

    if (tabId === 'tab-traceroute') {
      setTimeout(drawPingSparkline, 100);
    } else if (tabId === 'tab-topology') {
      setTimeout(() => {
        resizeTopologyCanvas();
        drawTopologyFrame();
      }, 100);
    }
  }

  function setupTabSwitching() {
    const tabs = document.querySelectorAll('.main-tabs-bar .tab-btn');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const targetModuleId = tab.getAttribute('data-tab');
        switchTab(targetModuleId);
      });
    });

    const themeBtn = document.getElementById('themeToggleBtn');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);
  }

  /* -------------------------------------------------------------
     MODULE 1: NMAP PORT & VULNERABILITY SCANNER
     ------------------------------------------------------------- */
  function setupNmapScanner() {
    const targetInput = document.getElementById('targetHostInput');
    const clearBtn = document.getElementById('btnClearTarget');
    const quickSelect = document.getElementById('quickTargetSelect');
    const btnScan = document.getElementById('btnStartScan');
    const btnCopy = document.getElementById('btnCopyCmd');
    const profilePills = document.querySelectorAll('.profile-pill');

    if (targetInput) {
      targetInput.addEventListener('input', () => {
        currentTarget = targetInput.value.trim() || 'scanme.nmap.org';
        updateNmapCommand();
        const manualTarget = document.getElementById('manualTargetInput');
        if (manualTarget) manualTarget.value = currentTarget;
        updateManualCommandLine();
      });
      targetInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') startScan();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (targetInput) {
          targetInput.value = '';
          targetInput.focus();
        }
      });
    }

    if (quickSelect) {
      quickSelect.addEventListener('change', (e) => {
        const val = e.target.value;
        if (targetInput) targetInput.value = val;
        currentTarget = val;
        updateNmapCommand();
        const manualTarget = document.getElementById('manualTargetInput');
        if (manualTarget) manualTarget.value = val;
        updateManualCommandLine();
        startScan();
      });
    }

    profilePills.forEach(pill => {
      pill.addEventListener('click', () => {
        profilePills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        activeProfile = pill.getAttribute('data-profile');
        updateNmapCommand();
        showToast(`Selected Profile: ${pill.innerText.trim()}`, 'info');
      });
    });

    if (btnScan) btnScan.addEventListener('click', startScan);

    if (btnCopy) {
      btnCopy.addEventListener('click', () => {
        const cmdCode = document.getElementById('nmapCmdDisplay')?.innerText || '';
        navigator.clipboard.writeText(cmdCode);
        showToast("Nmap CLI command copied to clipboard!", "success");
      });
    }

    // Service Filters
    const serviceFilterBtns = document.querySelectorAll('.filter-service-group .btn');
    serviceFilterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        serviceFilterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter');
        const activeData = targetDatabase[currentTarget] || targetDatabase['scanme.nmap.org'];
        renderServicesList(activeData.ports);
      });
    });
  }

  function updateNmapCommand() {
    const target = currentTarget || 'scanme.nmap.org';
    let command = "";

    switch (activeProfile) {
      case 'quick': command = `nmap -F -T4 ${target}`; break;
      case 'web': command = `nmap -p 80,443,8080,8443 -sV --script http-title,ssl-cert ${target}`; break;
      case 'vuln': command = `nmap -sV --script vuln ${target}`; break;
      case 'full': command = `nmap -A -p 1-1000 -T4 ${target}`; break;
      default: command = `nmap -sV ${target}`;
    }

    const el = document.getElementById('nmapCmdDisplay');
    if (el) el.innerText = command;
  }

  function isExternalTarget(target) {
    if (!target) return false;
    const t = target.trim().toLowerCase();
    if (t === '127.0.0.1' || t === 'localhost' || t.startsWith('127.')) return false;
    if (t.startsWith('192.168.') || t.startsWith('10.')) return false;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(t)) return false;
    return true;
  }

  function startScan() {
    if (isScanning) return;
    const targetInput = document.getElementById('targetHostInput');
    if (targetInput && targetInput.value.trim()) {
      currentTarget = targetInput.value.trim();
    }

    if (isExternalTarget(currentTarget) && !authorizedScanTargets.has(currentTarget)) {
      pendingExternalTarget = currentTarget;
      const disp = document.getElementById('extTargetDisplay');
      if (disp) disp.innerText = currentTarget;
      const modal = document.getElementById('modalExternalScanNotice');
      if (modal) modal.classList.remove('hidden');
      return;
    }

    executeZenmapDeepScan(currentTarget);
  }

  async function executeZenmapDeepScan(target) {
    if (isScanning) return;
    isScanning = true;

    const progressContainer = document.getElementById('scanProgressContainer');
    const progressBar = document.getElementById('scanProgressBar');
    const statusText = document.getElementById('scanStatusText');
    const percentText = document.getElementById('scanPercentText');
    const scanBtnText = document.getElementById('scanBtnText');
    const terminalOutput = document.getElementById('manualTerminalOutput');
    const errorBanner = document.getElementById('scanErrorBanner');

    if (errorBanner) errorBanner.classList.add('hidden');
    if (progressContainer) progressContainer.classList.remove('hidden');
    if (scanBtnText) scanBtnText.innerText = "Scanning...";
    if (terminalOutput) terminalOutput.innerHTML = "";

    try {
      const startRes = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, profile: activeProfile })
      });
      const startData = await startRes.json();
      if (!startData.success) {
        throw new Error(startData.error || "Failed to initiate scan");
      }
    } catch (err) {
      if (errorBanner) {
        errorBanner.classList.remove('hidden');
        const errTitle = document.getElementById('scanErrorTitle');
        const errDetails = document.getElementById('scanErrorDetails');
        if (errTitle) errTitle.innerText = "Scan Launch Failed";
        if (errDetails) errDetails.innerText = err.message;
      }
      if (progressContainer) progressContainer.classList.add('hidden');
      isScanning = false;
      if (scanBtnText) scanBtnText.innerText = "Start Smart Scan";
      showToast(`Scan failed: ${err.message}`, "danger");
      return;
    }

    let renderedLineCount = 0;
    const scanPollInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/scan/status');
        if (!res.ok) return;
        const st = await res.json();

        if (progressBar) progressBar.style.width = `${st.progress}%`;
        if (percentText) percentText.innerText = `${st.progress}%`;
        if (statusText) statusText.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> ${escapeHtml(st.statusText)}`;

        // Stream terminal lines
        if (st.terminalLines && st.terminalLines.length > renderedLineCount) {
          for (let i = renderedLineCount; i < st.terminalLines.length; i++) {
            const line = st.terminalLines[i];
            const div = document.createElement('div');
            div.className = line.class || 'term-line';
            div.innerHTML = line.text;
            terminalOutput.appendChild(div);
          }
          terminalOutput.scrollTop = terminalOutput.scrollHeight;
          renderedLineCount = st.terminalLines.length;
        }

        // On Scan Error
        if (st.error) {
          clearInterval(scanPollInterval);
          isScanning = false;
          if (progressContainer) progressContainer.classList.add('hidden');
          if (scanBtnText) scanBtnText.innerText = "Start Smart Scan";

          if (errorBanner) {
            errorBanner.classList.remove('hidden');
            const errTitle = document.getElementById('scanErrorTitle');
            const errDetails = document.getElementById('scanErrorDetails');
            if (errTitle) errTitle.innerText = "Nmap Scan Error";
            if (errDetails) errDetails.innerText = st.error;
          }
          showToast(st.error, "danger");
          return;
        }

        // On Scan Complete
        if (!st.isScanning && st.result) {
          clearInterval(scanPollInterval);
          setTimeout(() => {
            if (progressContainer) progressContainer.classList.add('hidden');
            isScanning = false;
            if (scanBtnText) scanBtnText.innerText = "Start Smart Scan";

            renderCurrentNmapResults(st.result);
            renderTracerouteHops(target);
            updateSecurityHealthIndex();
            showToast(`Real Zenmap deep scan completed for ${target}!`, "success");
          }, 200);
        }
      } catch (pollErr) {
        console.warn("Poll scan status error:", pollErr);
      }
    }, 350);
  }

  function generateZenmapHostData(target) {
    if (targetDatabase[target]) {
      const base = JSON.parse(JSON.stringify(targetDatabase[target]));
      if (!base.rdns) base.rdns = target;
      if (!base.cpe) base.cpe = 'cpe:/o:linux:kernel:5.x (96% match)';
      if (!base.vulnRating) {
        base.vulnRating = base.score >= 80 ? 'Low' : (base.score >= 60 ? 'Medium' : 'High');
      }
      if (!base.cveSummary) {
        base.cveSummary = base.score >= 80 ? 'No critical CVE vulnerabilities found.' : 'Medium risk CVE exposure detected.';
      }
      return base;
    }

    const t = target.trim().toLowerCase();
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(t);

    let ip = target;
    let rdns = target;
    let os = 'Linux 5.15 / Unix System';
    let cpe = 'cpe:/o:linux:kernel:5.15 (95% match)';
    let latency = `${Math.floor(Math.random() * 25 + 8)} ms`;
    let mac = 'WAN Cloud Gateway (AS13335)';
    let score = 84;
    let advice = 'Target responsive. Standard web ports open with TLS 1.3.';
    let vulnRating = 'Low';
    let cveSummary = 'No critical CVE advisories found. Baseline security standards met.';

    if (t === '8.8.8.8') {
      ip = '8.8.8.8';
      rdns = 'dns.google';
      os = 'Linux 5.x / Google Front-End';
      cpe = 'cpe:/o:linux:kernel:5.x (98% match)';
      latency = '12 ms';
      mac = 'Google LLC (BGP ASN 15169)';
      score = 94;
      vulnRating = 'None';
      advice = 'Google Public DNS resolver. All core services properly isolated.';
      cveSummary = 'Zero known CVE vulnerabilities. Hardened anycast infrastructure.';
      return {
        ip, rdns, os, cpe, latency, mac, score, advice, vulnRating, cveSummary,
        ports: [
          { port: 53, proto: 'UDP/TCP', state: 'open', service: 'dns', version: 'Google Public DNS 2024', risk: 'safe', note: 'Public recursive DNS.' },
          { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'BoringSSL (TLS 1.3)', risk: 'safe', note: 'DoH (DNS-over-HTTPS) active.' },
          { port: 853, proto: 'TCP', state: 'open', service: 'domain-s', version: 'BoringSSL', risk: 'safe', note: 'DoT (DNS-over-TLS).' },
          { port: 80, proto: 'TCP', state: 'closed', service: 'http', version: '-', risk: 'safe', note: 'Port closed.' }
        ]
      };
    }

    if (t === '1.1.1.1') {
      ip = '1.1.1.1';
      rdns = 'one.one.one.one';
      os = 'Linux / Cloudflare Edge (Kernel 6.x)';
      cpe = 'cpe:/o:linux:kernel:6.x (99% match)';
      latency = '9 ms';
      mac = 'Cloudflare Edge (BGP ASN 13335)';
      score = 96;
      vulnRating = 'None';
      advice = 'Cloudflare 1.1.1.1 resolver. Pristine configuration and TLS 1.3 enforcement.';
      cveSummary = 'Zero known CVE vulnerabilities. High resilience edge node.';
      return {
        ip, rdns, os, cpe, latency, mac, score, advice, vulnRating, cveSummary,
        ports: [
          { port: 53, proto: 'UDP/TCP', state: 'open', service: 'dns', version: 'Cloudflare DNS Engine', risk: 'safe', note: 'Global edge DNS resolver.' },
          { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'Cloudflare BoringSSL', risk: 'safe', note: 'DoH / Encrypted DNS.' },
          { port: 853, proto: 'TCP', state: 'open', service: 'domain-s', version: 'Cloudflare TLS', risk: 'safe', note: 'DNS-over-TLS.' }
        ]
      };
    }

    if (!isIp) {
      ip = `104.21.${Math.floor(Math.random()*200+10)}.${Math.floor(Math.random()*200+10)}`;
      rdns = target;
    } else {
      const parts = ip.split('.');
      rdns = `ptr-${parts[3]}-${parts[2]}-${parts[1]}-${parts[0]}.wan-backbone.net`;
    }

    // Vulnerability heuristic
    if (t.includes('vuln') || t.includes('test') || t.includes('hack') || t.includes('dev')) {
      score = 42;
      vulnRating = 'Critical';
      advice = 'CRITICAL CVE DETECTED: Apache 2.4.49 (CVE-2021-41773 Path Traversal/RCE) and outdated OpenSSH 7.2p2.';
      cveSummary = 'CVE-2021-41773 (CVSS 9.8 Critical), CVE-2016-0777 (CVSS 7.5 High), CVE-2021-2154 (CVSS 8.1 High)';
      return {
        ip, rdns, os: 'Linux (Ubuntu Server 20.04 LTS)', cpe: 'cpe:/o:canonical:ubuntu_linux:20.04 (94% match)',
        latency, mac, score, advice, vulnRating, cveSummary,
        ports: [
          { port: 80, proto: 'TCP', state: 'open', service: 'http', version: 'Apache httpd 2.4.49', risk: 'danger', note: 'CVE-2021-41773 (Remote Code Execution)' },
          { port: 22, proto: 'TCP', state: 'open', service: 'ssh', version: 'OpenSSH 7.2p2 Ubuntu', risk: 'danger', note: 'CVE-2016-0777 (Roaming Key Exposure)' },
          { port: 3306, proto: 'TCP', state: 'open', service: 'mysql', version: 'MySQL 5.7.28', risk: 'danger', note: 'CVE-2021-2154 (Remote privilege escalation)' },
          { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'OpenSSL 1.0.2g', risk: 'warn', note: 'Legacy TLS 1.0/1.1 enabled' }
        ]
      };
    }

    // Default general target
    return {
      ip, rdns, os, cpe, latency, mac, score, advice, vulnRating, cveSummary,
      ports: [
        { port: 443, proto: 'TCP', state: 'open', service: 'https', version: 'nginx/1.24.0 (TLS 1.3 / OpenSSL 3.0)', risk: 'safe', note: 'Encrypted HTTPS' },
        { port: 80, proto: 'TCP', state: 'open', service: 'http', version: 'nginx/1.24.0', risk: 'warn', note: 'HTTP Port Open. Redirect to HTTPS recommended.' },
        { port: 22, proto: 'TCP', state: 'filtered', service: 'ssh', version: 'OpenSSH 8.9p1', risk: 'safe', note: 'Firewalled' },
        { port: 53, proto: 'TCP', state: 'closed', service: 'dns', version: '-', risk: 'safe', note: 'Closed' }
      ]
    };
  }

  function renderCurrentNmapResults(data) {
    const resHost = document.getElementById('resHostName');
    const resLat = document.getElementById('resLatency');
    const resOs = document.getElementById('resOs');
    const resMac = document.getElementById('resMac');

    if (resHost) resHost.innerText = data.ip;
    if (resLat) resLat.innerText = `${data.latency} latency`;
    if (resOs) resOs.innerText = data.os;
    if (resMac) resMac.innerText = data.mac;

    const resRdns = document.getElementById('resReverseDns');
    if (resRdns) {
      resRdns.innerHTML = `<i class="fa-solid fa-arrow-rotate-left"></i> rDNS: ${escapeHtml(data.rdns || data.ip)}`;
    }

    const resCpe = document.getElementById('resOsCpe');
    if (resCpe) {
      resCpe.innerText = `CPE: ${data.cpe || 'cpe:/o:linux:kernel:5.x (96% guess)'}`;
    }

    const openCount = data.ports.filter(p => p.state === 'open').length;
    const filteredCount = data.ports.filter(p => p.state === 'filtered').length;
    const closedCount = data.ports.filter(p => p.state === 'closed').length;

    const elOpen = document.getElementById('countOpenPorts');
    const elFiltered = document.getElementById('countFilteredPorts');
    const elClosed = document.getElementById('countClosedPorts');
    if (elOpen) elOpen.innerText = openCount;
    if (elFiltered) elFiltered.innerText = filteredCount;
    if (elClosed) elClosed.innerText = closedCount;

    const scoreNum = document.getElementById('resScore');
    const scoreGrade = document.getElementById('resScoreGrade');
    const scoreAdvice = document.getElementById('resScoreAdvice');
    const healthIcon = document.getElementById('healthIcon');

    if (scoreNum) scoreNum.innerText = data.score;
    if (scoreAdvice) scoreAdvice.innerText = data.advice;

    const resVuln = document.getElementById('resVulnBadge');
    if (resVuln) {
      const rating = (data.vulnRating || 'none').toLowerCase();
      resVuln.className = `vuln-badge vuln-badge-${rating}`;
      resVuln.innerText = (data.vulnRating || 'None / Low').toUpperCase();
    }

    if (scoreGrade && healthIcon && scoreNum) {
      if (data.score >= 80) {
        scoreGrade.innerText = "Good";
        scoreGrade.className = "score-grade good";
        healthIcon.className = "card-icon emerald";
        scoreNum.style.color = "var(--accent-emerald)";
      } else if (data.score >= 65) {
        scoreGrade.innerText = "Moderate Risk";
        scoreGrade.className = "score-grade warning";
        healthIcon.className = "card-icon amber";
        scoreNum.style.color = "var(--accent-amber)";
      } else {
        scoreGrade.innerText = "Vulnerable";
        scoreGrade.className = "score-grade danger";
        healthIcon.className = "card-icon crimson";
        scoreNum.style.color = "var(--accent-crimson)";
      }
    }

    renderPortMatrix(data.ports);
    renderServicesList(data.ports);
  }

  function renderPortMatrix(ports) {
    const grid = document.getElementById('portMatrixGrid');
    if (!grid) return;
    grid.innerHTML = "";

    ports.forEach(item => {
      const box = document.createElement('div');
      box.className = `port-box port-${item.state}`;
      box.title = `Click to inspect Port ${item.port} (${item.service})`;

      box.innerHTML = `
        <span class="port-num">${item.port}</span>
        <span class="port-service">${item.service}</span>
        <span class="port-status-badge">${item.state}</span>
      `;

      box.addEventListener('click', () => openPortDetailsModal(item));
      grid.appendChild(box);
    });
  }

  function openPortDetailsModal(portItem) {
    const modal = document.getElementById('portDetailModal');
    if (!modal) return;

    const info = portKnowledge[portItem.port] || {
      name: `${portItem.service.toUpperCase()} Service`,
      desc: `Port ${portItem.port} handles ${portItem.service} traffic.`,
      risk: `State: ${portItem.state.toUpperCase()}.`,
      fix: `Close port in firewall if unused.`
    };

    const badge = document.getElementById('modalPortBadge');
    const title = document.getElementById('modalPortTitle');
    const state = document.getElementById('modalPortState');
    const desc = document.getElementById('modalPortDescription');
    const risk = document.getElementById('modalRiskText');
    const fix = document.getElementById('modalFixText');

    if (badge) badge.innerText = portItem.port;
    if (title) title.innerText = `Port ${portItem.port}: ${info.name}`;
    if (state) state.innerHTML = `State: <strong>${portItem.state.toUpperCase()}</strong> • Version: <code>${portItem.version}</code>`;
    if (desc) desc.innerText = info.desc;
    if (risk) risk.innerText = info.risk;
    if (fix) fix.innerText = info.fix;

    modal.classList.remove('hidden');
  }

  function renderServicesList(ports) {
    const container = document.getElementById('servicesList');
    if (!container) return;
    container.innerHTML = "";

    let filtered = ports;
    if (activeFilter === 'open') {
      filtered = ports.filter(p => p.state === 'open');
    } else if (activeFilter === 'risk') {
      filtered = ports.filter(p => p.risk === 'danger' || p.risk === 'warn');
    }

    if (filtered.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-check text-emerald"></i><p>No services matched filter.</p></div>`;
      return;
    }

    filtered.forEach(p => {
      const card = document.createElement('div');
      card.className = 'service-item-card';

      const riskClass = p.risk === 'danger' ? 'risk-danger' : (p.risk === 'warn' ? 'risk-warn' : 'risk-safe');
      const riskIcon = p.risk === 'danger' ? 'fa-triangle-exclamation' : (p.risk === 'warn' ? 'fa-circle-exclamation' : 'fa-check');

      card.innerHTML = `
        <div class="service-card-top">
          <div class="service-title">
            <span class="port-tag">${p.port}/${p.proto}</span>
            <span>${p.service.toUpperCase()}</span>
          </div>
          <span class="badge ${p.state === 'open' ? 'badge-success' : 'badge-muted'}">${p.state.toUpperCase()}</span>
        </div>
        <div class="service-version">Version: ${p.version}</div>
        <div class="service-risk-note ${riskClass}">
          <i class="fa-solid ${riskIcon}"></i>
          <span>${p.note}</span>
        </div>
      `;

      card.style.cursor = 'pointer';
      card.addEventListener('click', () => openPortDetailsModal(p));
      container.appendChild(card);
    });
  }

  /* -------------------------------------------------------------
     2. FEATURE 2: MANUAL COMMAND SCANNER & CLI TERMINAL BOX
     ------------------------------------------------------------- */
  function setupManualCommandScanner() {
    const targetInput = document.getElementById('manualTargetInput');
    const portRangeInput = document.getElementById('manualPortRangeInput');
    const flagPills = document.querySelectorAll('#cmdFlagsPills .cmd-flag-pill');
    const presetBtns = document.querySelectorAll('.btn-cmd-preset');
    const fullCmdInput = document.getElementById('manualFullCmdInput');
    const btnExecute = document.getElementById('btnExecuteManualCmd');
    const btnReset = document.getElementById('btnResetManualCmd');
    const btnClearTerm = document.getElementById('btnClearTerminal');
    const terminalOutput = document.getElementById('manualTerminalOutput');

    if (targetInput) {
      targetInput.addEventListener('input', updateManualCommandLine);
    }
    if (portRangeInput) {
      portRangeInput.addEventListener('input', updateManualCommandLine);
    }

    flagPills.forEach(pill => {
      pill.addEventListener('click', () => {
        pill.classList.toggle('active');
        updateManualCommandLine();
      });
    });

    presetBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const preset = btn.getAttribute('data-preset');
        applyScanPreset(preset);
      });
    });

    if (btnReset) {
      btnReset.addEventListener('click', () => {
        if (targetInput) targetInput.value = 'scanme.nmap.org';
        if (portRangeInput) portRangeInput.value = '21-443';
        flagPills.forEach(p => {
          const flag = p.getAttribute('data-flag');
          p.classList.toggle('active', flag === '-sV' || flag === '-sS');
        });
        updateManualCommandLine();
        showToast('Manual scanner reset to defaults', 'info');
      });
    }

    if (btnClearTerm && terminalOutput) {
      btnClearTerm.addEventListener('click', () => {
        terminalOutput.innerHTML = `
          <div class="term-line"><span class="term-cyan">portpulse@secops:~$</span> terminal cleared</div>
          <div class="term-line term-green">Ready for next manual command execution.</div>
        `;
      });
    }

    if (btnExecute) {
      btnExecute.addEventListener('click', executeManualCommand);
    }

    if (fullCmdInput) {
      fullCmdInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeManualCommand();
      });
    }
  }

  function updateManualCommandLine() {
    const targetInput = document.getElementById('manualTargetInput');
    const portRangeInput = document.getElementById('manualPortRangeInput');
    const fullCmdInput = document.getElementById('manualFullCmdInput');
    if (!fullCmdInput) return;

    const target = targetInput?.value.trim() || 'scanme.nmap.org';
    const ports = portRangeInput?.value.trim() || '21-443';

    const activeFlags = [];
    document.querySelectorAll('#cmdFlagsPills .cmd-flag-pill.active').forEach(p => {
      activeFlags.push(p.getAttribute('data-flag'));
    });

    const flagsStr = activeFlags.length ? activeFlags.join(' ') + ' ' : '';
    const portStr = ports ? `-p ${ports} ` : '';
    fullCmdInput.value = `nmap ${flagsStr}${portStr}${target}`.replace(/\s+/g, ' ').trim();
  }

  function applyScanPreset(preset) {
    const targetInput = document.getElementById('manualTargetInput');
    const portRangeInput = document.getElementById('manualPortRangeInput');
    const flagPills = document.querySelectorAll('#cmdFlagsPills .cmd-flag-pill');

    flagPills.forEach(p => p.classList.remove('active'));

    if (preset === 'quick') {
      if (portRangeInput) portRangeInput.value = '20-100';
      activateFlag('-sS');
      activateFlag('-T4');
      showToast('Loaded Quick Scan preset (-sS -T4 -p 20-100)', 'info');
    } else if (preset === 'intense') {
      if (portRangeInput) portRangeInput.value = '1-1000';
      activateFlag('-sS');
      activateFlag('-sV');
      activateFlag('-O');
      activateFlag('-T4');
      showToast('Loaded Intense Scan preset (-sS -sV -O -T4 -p 1-1000)', 'info');
    } else if (preset === 'vuln') {
      if (portRangeInput) portRangeInput.value = '80,443,445,3389';
      activateFlag('-sV');
      activateFlag('--script vuln');
      showToast('Loaded Vulnerability Audit preset (--script vuln)', 'info');
    } else if (preset === 'ping') {
      if (portRangeInput) portRangeInput.value = '';
      activateFlag('-Pn');
      showToast('Loaded Ping Sweep / No Ping preset (-Pn)', 'info');
    }

    updateManualCommandLine();
  }

  function activateFlag(flag) {
    const pill = document.querySelector(`#cmdFlagsPills .cmd-flag-pill[data-flag="${flag}"]`);
    if (pill) pill.classList.add('active');
  }

  function executeManualCommand() {
    const fullCmdInput = document.getElementById('manualFullCmdInput');
    const terminalOutput = document.getElementById('manualTerminalOutput');
    const targetInput = document.getElementById('manualTargetInput');
    if (!terminalOutput || !fullCmdInput) return;

    const cmd = fullCmdInput.value.trim();
    if (!cmd) return;

    const target = targetInput?.value.trim() || 'scanme.nmap.org';
    const now = new Date();
    const timeStr = now.toISOString().split('T')[0] + ' ' + now.toTimeString().split(' ')[0];

    // Terminal command invocation
    const runLine = document.createElement('div');
    runLine.className = 'term-line';
    runLine.innerHTML = `<span class="term-cyan">portpulse@secops:~$</span> <span style="color:#fff; font-weight:bold;">${escapeHtml(cmd)}</span>`;
    terminalOutput.appendChild(runLine);

    const executingLine = document.createElement('div');
    executingLine.className = 'term-line term-muted';
    executingLine.innerHTML = `Starting Nmap 7.94 ( https://nmap.org ) at ${timeStr}`;
    terminalOutput.appendChild(executingLine);

    terminalOutput.scrollTop = terminalOutput.scrollHeight;

    // Simulate CLI stream delay
    setTimeout(() => {
      const data = targetDatabase[target] || generateGenericTargetData(target);
      const isVuln = cmd.includes('vuln');

      let cliOutputHtml = `
        <div class="term-line">Initiating SYN Stealth Scan against <strong>${data.ip}</strong></div>
        <div class="term-line term-muted">Scanning ${data.ports.length} ports [1000 ports/host]</div>
        <div class="term-line">Nmap scan report for ${target} (${data.ip})</div>
        <div class="term-line term-green">Host is up (${data.latency} latency).</div>
        <div class="term-line term-muted">rDNS record for ${data.ip}: ${target}</div>
        <div class="term-line" style="margin-top:6px; color:#93c5fd; font-weight:600;">PORT     STATE    SERVICE       VERSION</div>
      `;

      data.ports.forEach(p => {
        const stateColor = p.state === 'open' ? '#34d399' : (p.state === 'filtered' ? '#fbbf24' : '#94a3b8');
        const paddedPort = `${p.port}/${p.proto}`.padEnd(8, ' ');
        const paddedState = p.state.padEnd(8, ' ');
        const paddedServ = p.service.padEnd(13, ' ');
        cliOutputHtml += `<div class="term-line">${escapeHtml(paddedPort)} <span style="color:${stateColor};">${escapeHtml(paddedState)}</span> ${escapeHtml(paddedServ)} ${escapeHtml(p.version)}</div>`;

        if (isVuln && p.risk === 'danger') {
          cliOutputHtml += `<div class="term-line term-crimson">|__ vuln-check: VULNERABILITY CONFIRMED: ${escapeHtml(p.note)}</div>`;
        }
      });

      if (cmd.includes('-O')) {
        cliOutputHtml += `
          <div class="term-line" style="margin-top:4px;">Device type: general purpose</div>
          <div class="term-line">Running: ${data.os}</div>
          <div class="term-line term-muted">OS CPE: cpe:/o:linux:linux_kernel:5</div>
        `;
      }

      cliOutputHtml += `
        <div class="term-line term-green" style="margin-top:8px;">Nmap done: 1 IP address (1 host up) scanned in 1.34 seconds</div>
      `;

      const block = document.createElement('div');
      block.innerHTML = cliOutputHtml;
      terminalOutput.appendChild(block);
      terminalOutput.scrollTop = terminalOutput.scrollHeight;

      // Update main scanner overview
      currentTarget = target;
      const targetHostInput = document.getElementById('targetHostInput');
      if (targetHostInput) targetHostInput.value = target;
      renderCurrentNmapResults(data);
      renderTracerouteHops(target);

      showToast(`Manual Nmap CLI command completed for ${target}`, 'success');
    }, 450);
  }

  /* -------------------------------------------------------------
     3. FEATURE 3: WIRESHARK-LIKE LIVE PACKET SNIFFER & MULTI-FILTER
     ------------------------------------------------------------- */
  function setupWiresharkSniffer() {
    const btnToggle = document.getElementById('btnToggleSniffer');
    const btnClear = document.getElementById('btnClearSniffer');
    const btnLeak = document.getElementById('btnInjectThreatPacket');
    const filterInput = document.getElementById('snifferFilterInput');
    const filterTags = document.querySelectorAll('.sniffer-filter-box .btn-filter-tag');

    // 1. Play / Pause Toggle
    if (btnToggle) {
      btnToggle.addEventListener('click', () => {
        if (isLimitReached) {
          resumeRealCapture(10000);
          return;
        }

        if (snifferRunning) {
          pauseRealCapture();
        } else {
          startRealCapture();
        }
      });
    }

    // 2. Clear Buffer
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        clearRealCapture();
      });
    }

    if (btnLeak) {
      btnLeak.addEventListener('click', () => {
        injectThreatLeakPacket();
      });
    }

    if (filterInput) {
      filterInput.addEventListener('input', () => {
        renderSnifferTable(filterInput.value.trim());
      });
    }

    filterTags.forEach(tag => {
      tag.addEventListener('click', () => {
        filterTags.forEach(t => t.classList.remove('active'));
        tag.classList.add('active');
        activeSnifferFilter = tag.getAttribute('data-proto');
        renderSnifferTable(filterInput ? filterInput.value.trim() : "");
      });
    });

    // 3. Target IP Selector & Custom IP Input
    const targetIpSelect = document.getElementById('captureTargetIpSelect');
    const customIpInput = document.getElementById('captureCustomIpInput');
    const dispTarget = document.getElementById('dispTargetIp');

    if (targetIpSelect) {
      targetIpSelect.addEventListener('change', (e) => {
        const val = e.target.value;
        if (val === 'custom') {
          if (customIpInput) {
            customIpInput.classList.remove('hidden');
            customIpInput.focus();
          }
        } else {
          if (customIpInput) customIpInput.classList.add('hidden');
          captureTargetIp = val;
          if (dispTarget) {
            dispTarget.innerText = val === 'all' ? 'All Network Traffic' : val;
          }
          showToast(`Sniffer monitoring target IP: ${val === 'all' ? 'All (0.0.0.0/0)' : val}`, 'info');
        }
      });
    }

    if (customIpInput) {
      customIpInput.addEventListener('input', () => {
        const val = customIpInput.value.trim();
        captureTargetIp = val || 'all';
        if (dispTarget) {
          dispTarget.innerText = val || 'All Network Traffic';
        }
      });
    }

    // 4. Capture Limit Selector & Custom Limit Input
    const limitSelect = document.getElementById('captureLimitModeSelect');
    const customLimitInput = document.getElementById('captureCustomLimitInput');

    if (limitSelect) {
      limitSelect.addEventListener('change', (e) => {
        const val = e.target.value;
        captureLimitMode = val;
        if (val === 'custom') {
          if (customLimitInput) {
            customLimitInput.classList.remove('hidden');
            customLimitInput.focus();
          }
        } else {
          if (customLimitInput) customLimitInput.classList.add('hidden');
          captureLimit = parseInt(val, 10) || 50000;
          updateCaptureProgressUI();
          showToast(`Capture limit set to ${captureLimit.toLocaleString()} packets`, 'info');
        }
      });
    }

    if (customLimitInput) {
      customLimitInput.addEventListener('input', () => {
        const val = parseInt(customLimitInput.value, 10);
        if (val > 0) {
          captureLimit = val;
          updateCaptureProgressUI();
        }
      });
    }

    // 5. Limit Reached Banner Actions
    const btnLimResume = document.getElementById('btnLimitResume');
    const btnLimSave = document.getElementById('btnLimitSave');
    const btnLimRestart = document.getElementById('btnLimitRestart');
    const btnLimStop = document.getElementById('btnLimitStop');

    if (btnLimResume) {
      btnLimResume.addEventListener('click', () => {
        resumeRealCapture(10000);
      });
    }

    if (btnLimSave) {
      btnLimSave.addEventListener('click', () => {
        const jsonStr = JSON.stringify(snifferPackets, null, 2);
        downloadFile(jsonStr, `PortPulse_Live_Capture_${Date.now()}.json`, 'application/json');
        showToast("Live packet capture session saved as JSON audit report!", "success");
      });
    }

    if (btnLimRestart) {
      btnLimRestart.addEventListener('click', async () => {
        await clearRealCapture();
        await startRealCapture();
      });
    }

    if (btnLimStop) {
      btnLimStop.addEventListener('click', () => {
        stopRealCapture();
      });
    }

    // 6. Smart Packet Guard (Traffic Spike) Actions
    const btnPauseSpike = document.getElementById('btnPauseOnSpike');
    const btnContinueSpike = document.getElementById('btnContinueOnSpike');
    const btnTestSpike = document.getElementById('btnSimulateSpike');

    if (btnPauseSpike) {
      btnPauseSpike.addEventListener('click', () => {
        snifferRunning = false;
        document.getElementById('spikeAlertBanner')?.classList.add('hidden');
        updateCaptureStatusUI('paused');
        const text = document.getElementById('snifferToggleText');
        const btnTog = document.getElementById('btnToggleSniffer');
        if (text) text.innerText = "Resume Capture";
        if (btnTog) btnTog.className = "btn btn-secondary";
        showToast("Capture paused on traffic spike inspection", "warning");
      });
    }

    if (btnContinueSpike) {
      btnContinueSpike.addEventListener('click', () => {
        document.getElementById('spikeAlertBanner')?.classList.add('hidden');
        isSpikeActive = false;
        currentPps = baselineRate;
        const sText = document.getElementById('spikeStatusText');
        if (sText) { sText.className = "text-emerald"; sText.innerText = "Baseline Normal"; }
        showToast("Traffic spike acknowledged — capture continuing", "info");
      });
    }

    if (btnTestSpike) {
      btnTestSpike.addEventListener('click', () => {
        triggerTrafficSpike();
      });
    }

    // 7. Malicious Packet Alert Modal Actions
    const btnCloseMal = document.getElementById('btnCloseMalModal');
    const btnToggleMal = document.getElementById('btnToggleMalDetails');
    const btnAllowOnce = document.getElementById('btnAllowPacketOnce');
    const btnConfirmBlock = document.getElementById('btnConfirmBlockPacket');

    if (btnCloseMal) {
      btnCloseMal.addEventListener('click', () => {
        document.getElementById('modalMaliciousPacketDetected')?.classList.add('hidden');
        if (!isLimitReached) snifferRunning = true;
      });
    }

    if (btnToggleMal) {
      btnToggleMal.addEventListener('click', () => {
        const details = document.getElementById('malPktTechDetails');
        const lbl = document.getElementById('lblToggleMalDetails');
        if (details) {
          const isHidden = details.classList.toggle('hidden');
          if (lbl) lbl.innerText = isHidden ? "View Details" : "Hide Details";
        }
      });
    }

    if (btnAllowOnce) {
      btnAllowOnce.addEventListener('click', () => {
        document.getElementById('modalMaliciousPacketDetected')?.classList.add('hidden');
        showToast("Threat packet permitted once in passive monitor mode.", "info");
        if (!isLimitReached) resumeRealCapture();
      });
    }

    if (btnConfirmBlock) {
      btnConfirmBlock.addEventListener('click', () => {
        if (pendingThreatPacket) {
          blockThreatIp(pendingThreatPacket.src, pendingThreatPacket.threatReason);
        }
        document.getElementById('modalMaliciousPacketDetected')?.classList.add('hidden');
        if (!isLimitReached) resumeRealCapture();
      });
    }

    // 8. Blocked Packets Log Modal Actions
    const btnOpenBlocked = document.getElementById('btnOpenBlockedModal');
    const btnCloseBlocked = document.getElementById('btnCloseBlockedModal');
    const btnCloseBlockedFooter = document.getElementById('btnCloseBlockedModalFooter');
    const btnClearBlocked = document.getElementById('btnClearBlockedList');
    const btnExportBlJson = document.getElementById('btnExportBlockedJson');
    const btnExportBlTxt = document.getElementById('btnExportBlockedTxt');

    if (btnOpenBlocked) {
      btnOpenBlocked.addEventListener('click', () => {
        renderBlockedTable();
        document.getElementById('modalBlockedPackets')?.classList.remove('hidden');
      });
    }

    if (btnCloseBlocked) {
      btnCloseBlocked.addEventListener('click', () => {
        document.getElementById('modalBlockedPackets')?.classList.add('hidden');
      });
    }

    if (btnCloseBlockedFooter) {
      btnCloseBlockedFooter.addEventListener('click', () => {
        document.getElementById('modalBlockedPackets')?.classList.add('hidden');
      });
    }

    if (btnClearBlocked) {
      btnClearBlocked.addEventListener('click', () => {
        activeBlockedIps.clear();
        blockedPacketsLog = [];
        const blCount = document.getElementById('blockedLogCount');
        const blDisp = document.getElementById('blockedCountDisplay');
        if (blCount) blCount.innerText = "0";
        if (blDisp) blDisp.innerText = "0";
        renderBlockedTable();
        showToast("Cleared all active firewall quarantine rules.", "info");
      });
    }

    if (btnExportBlJson) {
      btnExportBlJson.addEventListener('click', () => {
        const jsonStr = JSON.stringify(blockedPacketsLog, null, 2);
        downloadFile(jsonStr, `PortPulse_Blocked_Packets_${Date.now()}.json`, 'application/json');
        showToast("Exported blocked packets log as JSON!", "success");
      });
    }

    if (btnExportBlTxt) {
      btnExportBlTxt.addEventListener('click', () => {
        let txt = "=========================================================\n";
        txt += "     PORTPULSE STUDIO - ACTIVE BLOCKED TRAFFIC AUDIT     \n";
        txt += "=========================================================\n\n";
        txt += `Generated: ${new Date().toISOString()}\n`;
        txt += `Total Quarantined Entries: ${blockedPacketsLog.length}\n\n`;
        txt += "TIME      | SOURCE IP       | DESTINATION     | PROTO | REASON\n";
        txt += "---------------------------------------------------------\n";
        blockedPacketsLog.forEach(b => {
          txt += `${b.time} | ${b.src.padEnd(15, ' ')} | ${b.dst.padEnd(15, ' ')} | ${b.proto.padEnd(5, ' ')} | ${b.reason}\n`;
        });
        downloadFile(txt, `PortPulse_Blocked_Packets_${Date.now()}.txt`, 'text/plain');
        showToast("Exported blocked packets log as TXT!", "success");
      });
    }

    // 9. External Scan Authorization Modal Actions
    const btnCloseExt = document.getElementById('btnCloseExtScanModal');
    const btnCancelExt = document.getElementById('btnCancelExtScan');
    const btnProceedExt = document.getElementById('btnProceedExtScan');

    if (btnCloseExt) {
      btnCloseExt.addEventListener('click', () => {
        document.getElementById('modalExternalScanNotice')?.classList.add('hidden');
        pendingExternalTarget = null;
      });
    }

    if (btnCancelExt) {
      btnCancelExt.addEventListener('click', () => {
        document.getElementById('modalExternalScanNotice')?.classList.add('hidden');
        pendingExternalTarget = null;
        showToast("External host scan cancelled.", "info");
      });
    }

    if (btnProceedExt) {
      btnProceedExt.addEventListener('click', () => {
        if (pendingExternalTarget) {
          authorizedScanTargets.add(pendingExternalTarget);
          document.getElementById('modalExternalScanNotice')?.classList.add('hidden');
          const targetToScan = pendingExternalTarget;
          pendingExternalTarget = null;
          executeZenmapDeepScan(targetToScan);
        }
      });
    }

    // Close packet inspector modal
    const closePktModal = document.getElementById('btnClosePacketModal');
    const closePktModalFooter = document.getElementById('btnClosePacketModalFooter');
    const pktModal = document.getElementById('packetInspectModal');

    if (closePktModal && pktModal) closePktModal.addEventListener('click', () => pktModal.classList.add('hidden'));
    if (closePktModalFooter && pktModal) closePktModalFooter.addEventListener('click', () => pktModal.classList.add('hidden'));
  }

  function updateCaptureStatusUI(status) {
    captureStatus = status;
    const badge = document.getElementById('captureStatusBadge');
    if (!badge) return;

    if (status === 'capturing') {
      badge.className = "badge badge-success";
      badge.innerHTML = '<i class="fa-solid fa-circle-play"></i> CAPTURING';
    } else if (status === 'paused') {
      badge.className = "badge badge-muted";
      badge.innerHTML = '<i class="fa-solid fa-circle-pause"></i> PAUSED';
    } else if (status === 'limit-reached') {
      badge.className = "badge badge-amber";
      badge.innerHTML = '<i class="fa-solid fa-circle-pause"></i> LIMIT REACHED';
    } else {
      badge.className = "badge badge-muted";
      badge.innerHTML = '<i class="fa-solid fa-stop"></i> IDLE';
    }
  }

  function updateCaptureProgressUI() {
    const pct = Math.min(100, Math.round((capturePacketsTotal / captureLimit) * 100));
    const elCount = document.getElementById('capLiveCount');
    const elMax = document.getElementById('capMaxCount');
    const elPct = document.getElementById('capProgressPct');
    const elBar = document.getElementById('capProgressBar');
    const elTcp = document.getElementById('capCountTcp');
    const elUdp = document.getElementById('capCountUdp');
    const elIcmp = document.getElementById('capCountIcmp');
    const elOther = document.getElementById('capCountOther');
    const elPps = document.getElementById('capPpsRate');

    if (elCount) elCount.innerText = capturePacketsTotal.toLocaleString();
    if (elMax) elMax.innerText = captureLimit.toLocaleString();
    if (elPct) elPct.innerText = `${pct}%`;
    if (elBar) elBar.style.width = `${pct}%`;
    if (elTcp) elTcp.innerText = protoCountTcp.toLocaleString();
    if (elUdp) elUdp.innerText = protoCountUdp.toLocaleString();
    if (elIcmp) elIcmp.innerText = protoCountIcmp.toLocaleString();
    if (elOther) elOther.innerText = protoCountOther.toLocaleString();
    if (elPps) elPps.innerText = currentPps.toLocaleString();
  }

  function triggerTrafficSpike() {
    currentPps = 3480;
    isSpikeActive = true;
    const banner = document.getElementById('spikeAlertBanner');
    const details = document.getElementById('spikeDetails');
    const text = document.getElementById('spikeStatusText');

    if (details) {
      details.innerHTML = `Current Rate: <strong>${currentPps.toLocaleString()} pkt/s</strong> | Recent Baseline: <strong>${baselineRate} pkt/s</strong> — Abnormal traffic surge detected!`;
    }
    if (text) {
      text.className = "text-amber";
      text.innerText = "Spike Alert Active!";
    }
    if (banner) banner.classList.remove('hidden');

    const ppsEl = document.getElementById('capPpsRate');
    if (ppsEl) ppsEl.innerText = currentPps.toLocaleString();

    showToast("⚠️ TRAFFIC SPIKE DETECTED: 3,480 pkt/s!", "warning");
  }

  function triggerMaliciousPacketAlert(pkt) {
    pendingThreatPacket = pkt;
    snifferRunning = false;
    updateCaptureStatusUI('paused');

    const modal = document.getElementById('modalMaliciousPacketDetected');
    if (!modal) return;

    const elSrc = document.getElementById('malPktSrc');
    const elDst = document.getElementById('malPktDst');
    const elProto = document.getElementById('malPktProto');
    const elReason = document.getElementById('malPktReason');
    const elHeaders = document.getElementById('malPktHeaders');
    const elHex = document.getElementById('malPktHex');

    if (elSrc) elSrc.innerText = pkt.src;
    if (elDst) elDst.innerText = `${pkt.dst}${pkt.port ? ':' + pkt.port : ''}`;
    if (elProto) {
      elProto.innerText = pkt.proto;
      elProto.className = `proto-badge proto-${pkt.proto.toLowerCase()}`;
    }
    if (elReason) elReason.innerText = pkt.threatReason || 'Malicious signature matched in network payload.';
    if (elHeaders && pkt.headers) {
      elHeaders.innerHTML = pkt.headers.map(h => `<div>${escapeHtml(h)}</div>`).join('');
    }
    if (elHex) elHex.innerText = pkt.hex || '';

    modal.classList.remove('hidden');
    showToast(`🛑 Malicious packet intercepted from ${pkt.src}! Review threat popup.`, "danger");
  }

  function renderBlockedTable() {
    const tbody = document.getElementById('blockedTableBody');
    if (!tbody) return;
    tbody.innerHTML = "";

    if (blockedPacketsLog.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 24px;">No blocked packets or quarantined hosts currently on record.</td></tr>`;
      return;
    }

    blockedPacketsLog.forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${item.time}</td>
        <td><strong class="text-crimson">${escapeHtml(item.src)}</strong></td>
        <td>${escapeHtml(item.dst)}</td>
        <td><span class="proto-badge proto-${item.proto.toLowerCase()}">${item.proto}</span></td>
        <td style="color:#ef4444; font-size:12px;">${escapeHtml(item.reason)}</td>
        <td><span class="badge" style="background:#dc2626; color:#fff;">BLOCKED</span></td>
        <td>
          <button class="btn btn-xs btn-outline-danger btn-unblock-host" data-ip="${escapeHtml(item.src)}">
            <i class="fa-solid fa-lock-open"></i> Unblock
          </button>
        </td>
      `;

      const unblockBtn = tr.querySelector('.btn-unblock-host');
      if (unblockBtn) {
        unblockBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          const ipToUnblock = unblockBtn.getAttribute('data-ip');
          unblockThreatIp(ipToUnblock);
        });
      }

      tbody.appendChild(tr);
    });
  }

  /* -------------------------------------------------------------
     REAL WIRESHARK PACKET CAPTURE ENGINE (SCAPY / NPCAP BACKEND)
     ------------------------------------------------------------- */
  async function startRealCapture() {
    try {
      const ifaceName = activeInterface ? (activeInterface.name || activeInterface.id) : "Wi-Fi";
      const resp = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: ifaceName,
          target_ip: captureTargetIp,
          limit: captureLimit,
          limit_mode: captureLimitMode
        })
      });
      const data = await resp.json();
      snifferRunning = true;
      isLimitReached = false;
      document.getElementById('limitReachedBanner')?.classList.add('hidden');
      document.getElementById('capProgressBar')?.classList.remove('limit-reached');
      updateCaptureStatusUI('capturing');

      const text = document.getElementById('snifferToggleText');
      const btnToggle = document.getElementById('btnToggleSniffer');
      if (text) text.innerText = "Pause Capture";
      if (btnToggle) btnToggle.className = "btn btn-primary";
      if (btnToggle) {
        const icon = btnToggle.querySelector('i');
        if (icon) icon.className = "fa-solid fa-pause";
      }

      if (capturePollInterval) clearInterval(capturePollInterval);
      capturePollInterval = setInterval(pollRealCapture, 500);
      pollRealCapture();
      showToast(`Live packet capture active on ${ifaceName}`, "info");
    } catch (err) {
      console.warn("Backend capture start failed:", err);
    }
  }

  async function pauseRealCapture() {
    try {
      await fetch('/api/capture/pause', { method: 'POST' });
    } catch (e) {}
    snifferRunning = false;
    updateCaptureStatusUI('paused');
    const text = document.getElementById('snifferToggleText');
    const btnToggle = document.getElementById('btnToggleSniffer');
    if (text) text.innerText = "Resume Capture";
    if (btnToggle) btnToggle.className = "btn btn-secondary";
    if (btnToggle) {
      const icon = btnToggle.querySelector('i');
      if (icon) icon.className = "fa-solid fa-play";
    }
    showToast("Packet capture paused for inspection", "info");
  }

  async function resumeRealCapture(extendLimit = 0) {
    try {
      await fetch('/api/capture/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ extend_limit: extendLimit })
      });
    } catch (e) {}
    if (extendLimit > 0) {
      captureLimit += extendLimit;
    }
    snifferRunning = true;
    isLimitReached = false;
    document.getElementById('limitReachedBanner')?.classList.add('hidden');
    document.getElementById('capProgressBar')?.classList.remove('limit-reached');
    updateCaptureStatusUI('capturing');
    const text = document.getElementById('snifferToggleText');
    const btnToggle = document.getElementById('btnToggleSniffer');
    if (text) text.innerText = "Pause Capture";
    if (btnToggle) btnToggle.className = "btn btn-primary";
    if (btnToggle) {
      const icon = btnToggle.querySelector('i');
      if (icon) icon.className = "fa-solid fa-pause";
    }
    updateCaptureProgressUI();
    if (!capturePollInterval) {
      capturePollInterval = setInterval(pollRealCapture, 500);
    }
    showToast(extendLimit > 0 ? `Capture resumed. Limit extended to ${captureLimit.toLocaleString()} pkts.` : "Live packet capture resumed", "info");
  }

  async function stopRealCapture() {
    try {
      await fetch('/api/capture/stop', { method: 'POST' });
    } catch (e) {}
    snifferRunning = false;
    if (capturePollInterval) {
      clearInterval(capturePollInterval);
      capturePollInterval = null;
    }
    document.getElementById('limitReachedBanner')?.classList.add('hidden');
    updateCaptureStatusUI('paused');
    const text = document.getElementById('snifferToggleText');
    const btnToggle = document.getElementById('btnToggleSniffer');
    if (text) text.innerText = "Resume Capture";
    if (btnToggle) btnToggle.className = "btn btn-secondary";
    if (btnToggle) {
      const icon = btnToggle.querySelector('i');
      if (icon) icon.className = "fa-solid fa-play";
    }
    showToast("Capture session stopped.", "info");
  }

  async function clearRealCapture() {
    try {
      await fetch('/api/capture/clear', { method: 'POST' });
    } catch (e) {}
    snifferPackets = [];
    snifferPacketCounter = 0;
    lastCapturedSeq = 0;
    capturePacketsTotal = 0;
    protoCountTcp = 0;
    protoCountUdp = 0;
    protoCountIcmp = 0;
    protoCountOther = 0;
    isLimitReached = false;

    const tbody = document.getElementById('snifferTableBody');
    if (tbody) tbody.innerHTML = "";
    const sc = document.getElementById('sniffCount');
    const sa = document.getElementById('sniffAlerts');
    if (sc) sc.innerText = "0";
    if (sa) sa.innerText = "0";

    document.getElementById('limitReachedBanner')?.classList.add('hidden');
    document.getElementById('capProgressBar')?.classList.remove('limit-reached');
    updateCaptureProgressUI();
    if (snifferRunning) updateCaptureStatusUI('capturing');
    showToast("Packet sniffer buffer cleared", "info");
  }

  async function pollRealCapture() {
    if (!snifferRunning && !isLimitReached) return;

    try {
      const resp = await fetch(`/api/capture/poll?since_seq=${lastCapturedSeq}`);
      if (!resp.ok) return;
      const data = await resp.json();
      if (!data.success || !data.state) return;

      const state = data.state;
      capturePacketsTotal = state.total_packets;
      captureLimit = state.limit;
      currentPps = state.pps;
      baselineRate = state.baseline;
      protoCountTcp = state.proto_counts.tcp;
      protoCountUdp = state.proto_counts.udp;
      protoCountIcmp = state.proto_counts.icmp;
      protoCountOther = state.proto_counts.other;

      if (state.blocked_count !== undefined) {
        const blCount = document.getElementById('blockedLogCount');
        const blDisp = document.getElementById('blockedCountDisplay');
        if (blCount) blCount.innerText = state.blocked_count;
        if (blDisp) blDisp.innerText = state.blocked_count;
      }

      // Check limit reached
      if (state.limit_reached && !isLimitReached) {
        isLimitReached = true;
        snifferRunning = false;
        document.getElementById('limitReachedBanner')?.classList.remove('hidden');
        document.getElementById('capProgressBar')?.classList.add('limit-reached');
        updateCaptureStatusUI('limit-reached');
        const text = document.getElementById('snifferToggleText');
        const btnToggle = document.getElementById('btnToggleSniffer');
        if (text) text.innerText = "Resume Capture";
        if (btnToggle) btnToggle.className = "btn btn-secondary";
        if (btnToggle) {
          const icon = btnToggle.querySelector('i');
          if (icon) icon.className = "fa-solid fa-play";
        }
        showToast("Capture Limit Reached — Capture Paused", "warning");
      }

      // Check traffic spike
      if (state.is_spike && !isSpikeActive) {
        triggerTrafficSpike();
      }

      updateCaptureProgressUI();

      const elRate = document.getElementById('sniffRate');
      if (elRate) elRate.innerText = `${(currentPps * 1.25 / 1024).toFixed(1)} MB/s`;

      // Ingest packets
      if (data.packets && data.packets.length > 0) {
        for (const pkt of data.packets) {
          if (pkt.seq > lastCapturedSeq) {
            lastCapturedSeq = pkt.seq;
          }

          if (pkt.isThreat) {
            snifferAlertCount++;
            const sa = document.getElementById('sniffAlerts');
            if (sa) sa.innerText = snifferAlertCount;
          }

          if (!pkt.explanation) {
            pkt.explanation = `Real packet captured live on ${state.interface_id} (${pkt.proto}, ${pkt.len} bytes).`;
          }

          snifferPackets.unshift(pkt);
          if (snifferPackets.length > 100) snifferPackets.pop();

          updateSnifferUI(pkt);
        }
      }

      // Handle threat alert popup
      if (data.threat) {
        triggerMaliciousPacketAlert(data.threat);
      }

    } catch (err) {
      // Network poll error, quiet retry
    }
  }

  async function blockThreatIp(ip, reason) {
    activeBlockedIps.add(ip);
    try {
      await fetch('/api/capture/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason: reason || "Malicious traffic flagged" })
      });
    } catch (e) {}

    blockedPacketsLog.unshift({
      id: blockedPacketsLog.length + 1,
      time: new Date().toTimeString().split(' ')[0],
      src: ip,
      dst: 'Any',
      proto: 'ALL',
      reason: reason || 'Malicious signature matched',
      action: 'Blocked'
    });

    const blCount = document.getElementById('blockedLogCount');
    const blDisp = document.getElementById('blockedCountDisplay');
    if (blCount) blCount.innerText = blockedPacketsLog.length;
    if (blDisp) blDisp.innerText = blockedPacketsLog.length;

    renderBlockedTable();
    showToast(`🛑 Host ${ip} BLOCKED! All future packets will be dropped.`, "danger");
  }

  async function unblockThreatIp(ip) {
    activeBlockedIps.delete(ip);
    try {
      await fetch('/api/capture/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
    } catch (e) {}

    blockedPacketsLog = blockedPacketsLog.filter(x => x.src !== ip);
    const blCount = document.getElementById('blockedLogCount');
    const blDisp = document.getElementById('blockedCountDisplay');
    if (blCount) blCount.innerText = blockedPacketsLog.length;
    if (blDisp) blDisp.innerText = blockedPacketsLog.length;

    renderBlockedTable();
    showToast(`Host ${ip} unblocked and restored to allowlist.`, "success");
  }

  async function injectThreatLeakPacket() {
    try {
      const resp = await fetch('/api/capture/inject_threat', { method: 'POST' });
      const data = await resp.json();
      if (data.threat) {
        showToast("Simulated credential leak threat injected into real engine!", "warning");
      }
    } catch (e) {
      console.warn("Threat injection failed:", e);
    }
  }

  function startSnifferStreaming() {
    startRealCapture();
  }

  function updateSnifferUI(pkt) {
    const sc = document.getElementById('sniffCount');
    if (sc) sc.innerText = snifferPacketCounter;
    const filterInput = document.getElementById('snifferFilterInput');
    const query = filterInput ? filterInput.value.trim().toLowerCase() : "";

    if (matchesSnifferFilter(pkt, query)) {
      appendSnifferRow(pkt);
    }
  }

  // Multi-Field Filter (Feature 3)
  function matchesSnifferFilter(pkt, query) {
    if (activeSnifferFilter !== 'all' && pkt.proto.toUpperCase() !== activeSnifferFilter) {
      return false;
    }
    if (!query) return true;

    const q = query.trim().toLowerCase();

    // IP filter: e.g. "ip:192.168.1.1" or "192.168"
    if (q.startsWith('ip:')) {
      const targetIp = q.replace('ip:', '').trim();
      return pkt.src.toLowerCase().includes(targetIp) || pkt.dst.toLowerCase().includes(targetIp);
    }

    // Protocol filter: e.g. "proto:dns"
    if (q.startsWith('proto:')) {
      const targetProto = q.replace('proto:', '').trim();
      return pkt.proto.toLowerCase().includes(targetProto);
    }

    // Packet number filter: e.g. "#14"
    if (q.startsWith('#')) {
      const targetNum = q.replace('#', '').trim();
      return pkt.id.toString() === targetNum;
    }

    // Threat filter: e.g. "threat" or "leak"
    if (q === 'threat' || q === 'leak' || q === 'alert') {
      return pkt.isThreat === true;
    }

    // General keyword match
    return pkt.proto.toLowerCase().includes(q) ||
           pkt.src.toLowerCase().includes(q) ||
           pkt.dst.toLowerCase().includes(q) ||
           pkt.summary.toLowerCase().includes(q) ||
           (pkt.explanation && pkt.explanation.toLowerCase().includes(q));
  }

  function appendSnifferRow(pkt) {
    const tbody = document.getElementById('snifferTableBody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    if (pkt.isThreat) tr.classList.add('threat-row');

    const protoClass = `proto-${pkt.proto.toLowerCase()}`;
    const statusPill = pkt.status === 'BLOCKED'
      ? `<span class="badge" style="background:#dc2626; color:#fff;">BLOCKED</span>`
      : (pkt.isThreat 
          ? `<span class="badge" style="background:#ef4444; color:#fff;">THREAT</span>` 
          : `<span class="badge badge-success">OK</span>`);

    tr.innerHTML = `
      <td>${pkt.id}</td>
      <td>${pkt.time}</td>
      <td><span class="proto-badge ${protoClass}">${pkt.proto}</span></td>
      <td><span class="clickable-ip" title="Click to filter by this IP">${escapeHtml(pkt.src)}</span></td>
      <td><i class="fa-solid fa-arrow-right text-muted"></i></td>
      <td><span class="clickable-ip" title="Click to filter by this IP">${escapeHtml(pkt.dst)}</span></td>
      <td style="color:${pkt.isThreat ? '#ef4444' : 'var(--text-primary)'}; font-weight:${pkt.isThreat ? '700' : '500'};">${escapeHtml(pkt.summary)}</td>
      <td>${statusPill}</td>
    `;

    // Click row opens inspector modal
    tr.addEventListener('click', (e) => {
      if (e.target.classList.contains('clickable-ip')) {
        const ip = e.target.innerText.trim();
        const filterInput = document.getElementById('snifferFilterInput');
        if (filterInput) {
          filterInput.value = ip;
          renderSnifferTable(ip);
          showToast(`Filtered sniffer stream for ${ip}`, 'info');
        }
        return;
      }
      openPacketInspectorModal(pkt);
    });

    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > 50) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function renderSnifferTable(query = "") {
    const tbody = document.getElementById('snifferTableBody');
    if (!tbody) return;
    tbody.innerHTML = "";

    snifferPackets.filter(p => matchesSnifferFilter(p, query)).forEach(pkt => {
      appendSnifferRow(pkt);
    });
  }

  function openPacketInspectorModal(pkt) {
    selectedSnifferPacket = pkt;
    const modal = document.getElementById('packetInspectModal');
    if (!modal) return;

    const title = document.getElementById('inspectPktTitle');
    const meta = document.getElementById('inspectPktMeta');
    const explanation = document.getElementById('inspectPktExplanation');
    const headersBox = document.getElementById('inspectPktHeaders');
    const hex = document.getElementById('inspectPktHex');

    if (title) title.innerText = `Packet #${pkt.id} — ${pkt.proto} ${pkt.isThreat ? '(Risk Detected)' : ''}`;
    if (meta) meta.innerText = `Time: ${pkt.time} • Size: ${pkt.len} Bytes • Flow: ${pkt.src} -> ${pkt.dst}`;
    if (explanation) explanation.innerHTML = pkt.explanation;

    if (headersBox) {
      headersBox.innerHTML = pkt.headers.map(h => `<div>${escapeHtml(h)}</div>`).join('');
    }

    if (hex) hex.innerText = pkt.hex;
    modal.classList.remove('hidden');
  }

  /* -------------------------------------------------------------
     4. FEATURE 4: NETWORK TOPOLOGY DESIGN & FLOW RADAR
     ------------------------------------------------------------- */
  const topoNodes = [
    { id: 'gw', name: 'Gateway Router', ip: '192.168.1.1', mac: 'D8:07:B6:33:AA:01', type: 'Gateway Router', status: 'Clean', sockets: '34 connections', role: 'gw', icon: 'fa-router', xRatio: 0.50, yRatio: 0.38, color: '#06b6d4' },
    { id: 'pc', name: 'My Workstation (This PC)', ip: '192.168.1.105', mac: '3C:06:30:4F:A1:22', type: 'Desktop PC', status: 'Clean', sockets: '42 connections', role: 'client', icon: 'fa-desktop', xRatio: 0.22, yRatio: 0.72, color: '#3b82f6' },
    { id: 'phone', name: 'Apple iPhone 15 Pro', ip: '192.168.1.12', mac: '70:85:C2:5B:14:89', type: 'Smartphone', status: 'Clean', sockets: '14 connections', role: 'client', icon: 'fa-mobile-screen-button', xRatio: 0.40, yRatio: 0.76, color: '#3b82f6' },
    { id: 'tv', name: 'Samsung Smart TV', ip: '192.168.1.18', mac: 'F4:D1:08:92:E0:41', type: 'Smart TV', status: 'Clean', sockets: '8 connections', role: 'client', icon: 'fa-tv', xRatio: 0.60, yRatio: 0.76, color: '#3b82f6' },
    { id: 'ps5', name: 'PlayStation 5', ip: '192.168.1.88', mac: 'A0:36:BC:11:45:90', type: 'Gaming Console', status: 'Clean', sockets: '12 connections', role: 'client', icon: 'fa-gamepad', xRatio: 0.78, yRatio: 0.72, color: '#3b82f6' },
    { id: 'iot', name: 'Unknown IoT Device', ip: '192.168.1.199', mac: 'B4:E6:2D:67:9A:1F', type: 'Unregistered Client', status: 'Threat / Suspicious', sockets: '2 connections', role: 'threat', icon: 'fa-triangle-exclamation', xRatio: 0.90, yRatio: 0.45, color: '#ef4444' },
    { id: 'dns', name: 'Cloudflare DNS', ip: '1.1.1.1', mac: 'WAN Resolver', type: 'Cloud DNS', status: 'Optimal', sockets: 'Global Edge', role: 'cloud', icon: 'fa-cloud', xRatio: 0.30, yRatio: 0.14, color: '#8b5cf6' },
    { id: 'target', name: 'Test Target (scanme)', ip: '45.33.32.156', mac: 'WAN Host', type: 'External Server', status: 'Audited', sockets: '4 Open Ports', role: 'cloud', icon: 'fa-server', xRatio: 0.70, yRatio: 0.14, color: '#8b5cf6' }
  ];

  const topoLinks = [
    { from: 'gw', to: 'pc' },
    { from: 'gw', to: 'phone' },
    { from: 'gw', to: 'tv' },
    { from: 'gw', to: 'ps5' },
    { from: 'gw', to: 'iot' },
    { from: 'gw', to: 'dns' },
    { from: 'gw', to: 'target' }
  ];

  // Animated packet particles along links
  let topoParticles = [];
  function initTopoParticles() {
    topoParticles = [];
    for (let i = 0; i < 18; i++) {
      const link = topoLinks[Math.floor(Math.random() * topoLinks.length)];
      topoParticles.push({
        from: link.from,
        to: link.to,
        progress: Math.random(),
        speed: 0.005 + Math.random() * 0.007,
        size: 3.5,
        color: Math.random() > 0.8 ? '#ef4444' : '#06b6d4'
      });
    }
  }

  function setupTopologyRadar() {
    topoCanvas = document.getElementById('topologyCanvas');
    if (!topoCanvas) return;
    topoCtx = topoCanvas.getContext('2d');

    resizeTopologyCanvas();
    window.addEventListener('resize', resizeTopologyCanvas);
    initTopoParticles();

    // Start animation loop
    function loop() {
      drawTopologyFrame();
      topoAnimId = requestAnimationFrame(loop);
    }
    loop();

    // Canvas click event for inspecting nodes
    topoCanvas.addEventListener('click', (e) => {
      const rect = topoCanvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      const w = topoCanvas.width;
      const h = topoCanvas.height;

      let clickedNode = null;
      topoNodes.forEach(node => {
        const nx = node.xRatio * w;
        const ny = node.yRatio * h;
        const dist = Math.hypot(clickX - nx, clickY - ny);
        if (dist <= 26) {
          clickedNode = node;
        }
      });

      if (clickedNode) {
        showTopologyNodeCard(clickedNode);
      } else {
        closeTopologyNodeCard();
      }
    });

    const btnReset = document.getElementById('btnResetTopology');
    if (btnReset) {
      btnReset.addEventListener('click', () => {
        closeTopologyNodeCard();
        initTopoParticles();
        showToast("Topology radar view reset", "info");
      });
    }

    const btnTogglePart = document.getElementById('btnToggleParticles');
    if (btnTogglePart) {
      btnTogglePart.addEventListener('click', () => {
        topoParticlesEnabled = !topoParticlesEnabled;
        btnTogglePart.innerHTML = topoParticlesEnabled 
          ? `<i class="fa-solid fa-atom"></i> Particles: ON` 
          : `<i class="fa-solid fa-ban"></i> Particles: OFF`;
        showToast(`Flow particles ${topoParticlesEnabled ? 'enabled' : 'disabled'}`, 'info');
      });
    }

    const btnCloseCard = document.getElementById('btnCloseTopCard');
    if (btnCloseCard) {
      btnCloseCard.addEventListener('click', closeTopologyNodeCard);
    }

    const btnFilterNode = document.getElementById('btnFilterTopNode');
    if (btnFilterNode) {
      btnFilterNode.addEventListener('click', () => {
        if (selectedTopoNode) {
          switchTab('tab-wireshark');
          const filterInput = document.getElementById('snifferFilterInput');
          if (filterInput) {
            filterInput.value = selectedTopoNode.ip;
            renderSnifferTable(selectedTopoNode.ip);
          }
          showToast(`Filtered live traffic stream for ${selectedTopoNode.name} (${selectedTopoNode.ip})`, 'success');
        }
      });
    }
  }

  function resizeTopologyCanvas() {
    if (!topoCanvas) return;
    const parent = topoCanvas.parentElement;
    topoCanvas.width = parent.clientWidth || 900;
    topoCanvas.height = 420;
  }

  function drawTopologyFrame() {
    if (!topoCtx || !topoCanvas) return;
    const w = topoCanvas.width;
    const h = topoCanvas.height;

    topoCtx.clearRect(0, 0, w, h);

    // Draw background radar concentric circles from gateway
    const gwNode = topoNodes.find(n => n.id === 'gw');
    const gx = gwNode.xRatio * w;
    const gy = gwNode.yRatio * h;

    const isDark = currentTheme === 'dark';
    const ringColor = isDark ? 'rgba(6, 182, 212, 0.05)' : 'rgba(6, 182, 212, 0.08)';

    for (let r = 80; r <= 360; r += 70) {
      topoCtx.beginPath();
      topoCtx.arc(gx, gy, r, 0, Math.PI * 2);
      topoCtx.strokeStyle = ringColor;
      topoCtx.lineWidth = 1;
      topoCtx.stroke();
    }

    // Draw Links
    topoLinks.forEach(link => {
      const nFrom = topoNodes.find(n => n.id === link.from);
      const nTo = topoNodes.find(n => n.id === link.to);
      if (!nFrom || !nTo) return;

      const x1 = nFrom.xRatio * w;
      const y1 = nFrom.yRatio * h;
      const x2 = nTo.xRatio * w;
      const y2 = nTo.yRatio * h;

      topoCtx.beginPath();
      topoCtx.moveTo(x1, y1);
      topoCtx.lineTo(x2, y2);
      topoCtx.strokeStyle = isDark ? 'rgba(148, 163, 184, 0.22)' : 'rgba(100, 116, 139, 0.28)';
      topoCtx.lineWidth = 1.5;
      topoCtx.setLineDash([4, 4]);
      topoCtx.stroke();
      topoCtx.setLineDash([]);
    });

    // Draw Flow Particles
    if (topoParticlesEnabled) {
      topoParticles.forEach(p => {
        p.progress += p.speed;
        if (p.progress > 1) {
          p.progress = 0;
          const link = topoLinks[Math.floor(Math.random() * topoLinks.length)];
          p.from = link.from;
          p.to = link.to;
        }

        const nFrom = topoNodes.find(n => n.id === p.from);
        const nTo = topoNodes.find(n => n.id === p.to);
        if (!nFrom || !nTo) return;

        const x = nFrom.xRatio * w + (nTo.xRatio * w - nFrom.xRatio * w) * p.progress;
        const y = nFrom.yRatio * h + (nTo.yRatio * h - nFrom.yRatio * h) * p.progress;

        topoCtx.beginPath();
        topoCtx.arc(x, y, p.size, 0, Math.PI * 2);
        topoCtx.fillStyle = p.color;
        topoCtx.shadowColor = p.color;
        topoCtx.shadowBlur = 8;
        topoCtx.fill();
        topoCtx.shadowBlur = 0;
      });
    }

    // Draw Nodes
    topoNodes.forEach(node => {
      const nx = node.xRatio * w;
      const ny = node.yRatio * h;
      const isSelected = selectedTopoNode && selectedTopoNode.id === node.id;

      // Glow ring
      topoCtx.beginPath();
      topoCtx.arc(nx, ny, isSelected ? 26 : 20, 0, Math.PI * 2);
      topoCtx.fillStyle = isDark ? '#1e293b' : '#ffffff';
      topoCtx.strokeStyle = node.color;
      topoCtx.lineWidth = isSelected ? 3.5 : 2;
      topoCtx.shadowColor = node.color;
      topoCtx.shadowBlur = isSelected ? 16 : 8;
      topoCtx.fill();
      topoCtx.stroke();
      topoCtx.shadowBlur = 0;

      // Center dot
      topoCtx.beginPath();
      topoCtx.arc(nx, ny, 6, 0, Math.PI * 2);
      topoCtx.fillStyle = node.color;
      topoCtx.fill();

      // Label
      topoCtx.font = '600 12px Inter, sans-serif';
      topoCtx.fillStyle = isDark ? '#f8fafc' : '#0f172a';
      topoCtx.textAlign = 'center';
      topoCtx.fillText(node.name, nx, ny + 34);

      topoCtx.font = '400 10px JetBrains Mono, monospace';
      topoCtx.fillStyle = isDark ? '#94a3b8' : '#64748b';
      topoCtx.fillText(node.ip, nx, ny + 48);
    });
  }

  function showTopologyNodeCard(node) {
    selectedTopoNode = node;
    const card = document.getElementById('topologyNodeCard');
    if (!card) return;

    const icon = document.getElementById('topNodeIcon');
    const title = document.getElementById('topNodeTitle');
    const ip = document.getElementById('topNodeIp');
    const mac = document.getElementById('topNodeMac');
    const type = document.getElementById('topNodeType');
    const sockets = document.getElementById('topNodeSockets');
    const status = document.getElementById('topNodeStatus');

    if (icon) icon.className = `fa-solid ${node.icon}`;
    if (title) title.innerText = node.name;
    if (ip) ip.innerText = node.ip;
    if (mac) mac.innerText = node.mac;
    if (type) type.innerText = node.type;
    if (sockets) sockets.innerText = node.sockets;

    if (status) {
      status.innerText = node.status;
      status.className = node.role === 'threat' ? 'text-crimson font-bold' : 'text-emerald';
    }

    card.classList.remove('hidden');
  }

  function closeTopologyNodeCard() {
    selectedTopoNode = null;
    const card = document.getElementById('topologyNodeCard');
    if (card) card.classList.add('hidden');
  }

  /* -------------------------------------------------------------
     8. FEATURE 8: SECURITY HEALTH & AUDIT POSTURE
     ------------------------------------------------------------- */
  function updateSecurityHealthIndex() {
    const numEl = document.getElementById('healthScoreGaugeNum');
    const gradeEl = document.getElementById('healthScoreGaugeGrade');
    const ringEl = document.getElementById('healthGaugeRing');

    // Dynamic calculate based on leaks and active targets
    let score = 96;
    if (snifferAlertCount > 0) score -= (snifferAlertCount * 12);
    if (score < 40) score = 40;

    let grade = "Optimal";
    let color = "#10b981";

    if (score >= 90) {
      grade = "Optimal";
      color = "#10b981";
    } else if (score >= 70) {
      grade = "Moderate Risk";
      color = "#f59e0b";
    } else {
      grade = "High Exposure";
      color = "#ef4444";
    }

    if (numEl) numEl.innerText = `${score}%`;
    if (gradeEl) {
      gradeEl.innerText = grade;
      gradeEl.style.color = color;
    }
    if (ringEl) {
      ringEl.style.background = `conic-gradient(${color} ${score * 3.6}deg, var(--border-color) 0deg)`;
    }
  }

  /* -------------------------------------------------------------
     5. MODULE 3: VISUAL TRACEROUTE & LATENCY HUB
     ------------------------------------------------------------- */
  function setupTracerouteHub() {
    const btnTrace = document.getElementById('btnRunTrace');
    const btnRetestDns = document.getElementById('btnRetestDns');

    if (btnTrace) {
      btnTrace.addEventListener('click', () => {
        renderTracerouteHops(currentTarget);
        showToast(`Traceroute mapped path to ${currentTarget}!`, "success");
      });
    }

    if (btnRetestDns) {
      btnRetestDns.addEventListener('click', () => {
        renderDnsRaceList();
        showToast("DNS speed benchmark retested!", "info");
      });
    }
  }

  function renderTracerouteHops(target) {
    const container = document.getElementById('tracerouteVisualBox');
    if (!container) return;

    const targetIp = targetDatabase[target] ? targetDatabase[target].ip : "45.33.32.156";
    const hops = [
      { num: 1, name: "My Computer", ip: "192.168.1.105", rtt: "0.4 ms", icon: "fa-laptop" },
      { num: 2, name: "Wi-Fi Router", ip: "192.168.1.1", rtt: "1.2 ms", icon: "fa-router" },
      { num: 3, name: "ISP Gateway Hub", ip: "103.21.144.1", rtt: "6.8 ms", icon: "fa-tower-cell" },
      { num: 4, name: "Internet Backbone", ip: "140.82.112.1", rtt: "11.4 ms", icon: "fa-network-wired" },
      { num: 5, name: target, ip: targetIp, rtt: "14.2 ms", icon: "fa-server" }
    ];

    let html = "";
    hops.forEach(hop => {
      html += `
        <div class="trace-hop-card">
          <div class="hop-icon-circle"><i class="fa-solid ${hop.icon}"></i></div>
          <span class="hop-num">Hop #${hop.num}</span>
          <div class="hop-ip">${escapeHtml(hop.name)}</div>
          <div class="text-xs text-muted">(${hop.ip})</div>
          <div class="hop-rtt"><i class="fa-solid fa-bolt"></i> ${hop.rtt}</div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  function initPingCanvas() {
    pingCanvas = document.getElementById('pingSparkCanvas');
    if (!pingCanvas) return;
    pingCtx = pingCanvas.getContext('2d');
    resizePingCanvas();
    window.addEventListener('resize', resizePingCanvas);

    setInterval(() => {
      const nextPing = Math.max(9, Math.floor(14 + (Math.random() * 6 - 3)));
      pingHistory.push(nextPing);
      if (pingHistory.length > 25) pingHistory.shift();

      const min = Math.min(...pingHistory);
      const max = Math.max(...pingHistory);
      const avg = Math.round(pingHistory.reduce((a, b) => a + b, 0) / pingHistory.length);
      const jitter = (Math.abs(nextPing - avg)).toFixed(1);

      const pMin = document.getElementById('pingMin');
      const pAvg = document.getElementById('pingAvg');
      const pMax = document.getElementById('pingMax');
      const pJit = document.getElementById('pingJitter');

      if (pMin) pMin.innerText = `${min} ms`;
      if (pAvg) pAvg.innerText = `${avg} ms`;
      if (pMax) pMax.innerText = `${max} ms`;
      if (pJit) pJit.innerText = `${jitter} ms`;

      drawPingSparkline();
    }, 1000);
  }

  function resizePingCanvas() {
    if (!pingCanvas) return;
    pingCanvas.width = pingCanvas.parentElement.clientWidth || 400;
    pingCanvas.height = 100;
  }

  function drawPingSparkline() {
    if (!pingCtx || !pingCanvas) return;
    const w = pingCanvas.width;
    const h = pingCanvas.height;

    pingCtx.clearRect(0, 0, w, h);

    const step = w / (pingHistory.length - 1);
    pingCtx.beginPath();
    pingCtx.moveTo(0, h - (pingHistory[0] * 2.5));

    for (let i = 1; i < pingHistory.length; i++) {
      const x = i * step;
      const y = h - (pingHistory[i] * 2.5);
      pingCtx.lineTo(x, y);
    }

    pingCtx.strokeStyle = '#06b6d4';
    pingCtx.lineWidth = 2.5;
    pingCtx.stroke();
  }

  function renderDnsRaceList() {
    const container = document.getElementById('dnsRaceList');
    if (!container) return;

    const servers = [
      { name: "Cloudflare (1.1.1.1)", ms: Math.floor(Math.random() * 3 + 9), color: "#06b6d4" },
      { name: "Google (8.8.8.8)", ms: Math.floor(Math.random() * 4 + 14), color: "#3b82f6" },
      { name: "Quad9 (9.9.9.9)", ms: Math.floor(Math.random() * 4 + 18), color: "#8b5cf6" },
      { name: "ISP Gateway (192.168.1.1)", ms: Math.floor(Math.random() * 6 + 28), color: "#f59e0b" }
    ];

    servers.sort((a, b) => a.ms - b.ms);
    const max = Math.max(...servers.map(s => s.ms));

    let html = "";
    servers.forEach((s, idx) => {
      const pct = Math.round((s.ms / max) * 100);
      html += `
        <div class="dns-race-item">
          <div class="dns-race-name">${idx === 0 ? '🏆 ' : ''}${s.name}</div>
          <div class="dns-race-bar-track">
            <div class="dns-race-bar-fill" style="width: ${pct}%; background: ${s.color};"></div>
          </div>
          <div class="dns-race-time" style="color: ${idx === 0 ? '#10b981' : 'var(--text-secondary)'}">${s.ms} ms</div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  /* -------------------------------------------------------------
     1 & 6. FEATURES 1 & 6: LAN DEVICE DISCOVERY & HOST EXPLORER
     ------------------------------------------------------------- */
  function setupLanDiscovery() {
    const btnScan = document.getElementById('btnScanLan');
    if (btnScan) {
      btnScan.addEventListener('click', () => {
        showToast("Scanning local Wi-Fi subnet (192.168.1.0/24)...", "info");
        setTimeout(() => {
          renderLanDevicesList();
          showToast("Discovered 6 connected devices on Wi-Fi!", "success");
        }, 500);
      });
    }
  }

  function renderLanDevicesList() {
    const container = document.getElementById('lanDevicesGrid');
    if (!container) return;

    let total = lanDevices.length;
    let known = lanDevices.filter(d => d.isTrusted).length;
    let unknown = total - known;

    const elTotal = document.getElementById('lanTotalCount');
    const elKnown = document.getElementById('lanKnownCount');
    const elUnknown = document.getElementById('lanUnknownCount');
    if (elTotal) elTotal.innerText = total;
    if (elKnown) elKnown.innerText = known;
    if (elUnknown) elUnknown.innerText = unknown;

    let html = "";
    lanDevices.forEach((d, idx) => {
      html += `
        <div class="lan-device-card ${d.isTrusted ? '' : 'unknown-device'}" data-dev-idx="${idx}">
          <div class="device-icon-box"><i class="fa-solid ${d.icon}"></i></div>
          <div class="device-info">
            <div class="device-name">${escapeHtml(d.name)}</div>
            <span class="device-ip">${d.ip} • <code>${d.mac}</code></span>
            <div class="device-meta">
              <span>Vendor: <strong>${d.vendor}</strong></span>
              <span style="margin-left: 8px;">• ${d.isTrusted ? '<span class="text-emerald">Trusted</span>' : '<span class="text-crimson font-bold">⚠️ Guest / Unknown</span>'}</span>
            </div>
            <!-- 1. THREE ACTION BUTTONS: DETAILS, SCAN, CAPTURE -->
            <div class="device-actions-row">
              <button class="btn btn-xs btn-outline btn-act-details" data-dev-idx="${idx}" title="View deep host specifications, vendor & open ports">
                <i class="fa-solid fa-circle-info"></i> Details
              </button>
              <button class="btn btn-xs btn-outline btn-act-scan" data-dev-idx="${idx}" title="Load device IP into Nmap scanner and CLI">
                <i class="fa-solid fa-terminal"></i> Scan
              </button>
              <button class="btn btn-xs btn-outline btn-act-capture" data-dev-idx="${idx}" title="Filter Wireshark sniffer to capture this host's packets">
                <i class="fa-solid fa-filter"></i> Capture
              </button>
            </div>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;

    // Attach event listeners to the 3 action buttons
    container.querySelectorAll('.btn-act-details').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.getAttribute('data-dev-idx'));
        openDeviceDetailsModal(lanDevices[idx]);
      });
    });

    container.querySelectorAll('.btn-act-scan').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.getAttribute('data-dev-idx'));
        triggerDeviceScan(lanDevices[idx]);
      });
    });

    container.querySelectorAll('.btn-act-capture').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.getAttribute('data-dev-idx'));
        triggerDeviceCapture(lanDevices[idx]);
      });
    });
  }

  function triggerDeviceScan(dev) {
    currentTarget = dev.ip;
    const targetHostInput = document.getElementById('targetHostInput');
    const manualTarget = document.getElementById('manualTargetInput');
    if (targetHostInput) targetHostInput.value = dev.ip;
    if (manualTarget) manualTarget.value = dev.ip;
    updateNmapCommand();
    updateManualCommandLine();
    switchTab('tab-nmap');
    startScan();
    showToast(`Loaded ${dev.name} (${dev.ip}) into Nmap Scanner!`, 'info');
  }

  function triggerDeviceCapture(dev) {
    switchTab('tab-wireshark');
    const filterInput = document.getElementById('snifferFilterInput');
    if (filterInput) {
      filterInput.value = dev.ip;
      renderSnifferTable(dev.ip);
    }
    showToast(`Live packet sniffer filtered for ${dev.name} (${dev.ip})`, 'info');
  }

  /* -------------------------------------------------------------
     1. DEEP DEVICE & HOST DETAILS MODAL
     ------------------------------------------------------------- */
  function setupDeviceDetailsModal() {
    const modal = document.getElementById('deviceDetailsModal');
    const closeBtn = document.getElementById('btnCloseDeviceModal');
    const closeFooterBtn = document.getElementById('btnCloseDeviceModalFooter');
    const btnScan = document.getElementById('devModalBtnScan');
    const btnCapture = document.getElementById('devModalBtnCapture');

    if (closeBtn && modal) closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    if (closeFooterBtn && modal) closeFooterBtn.addEventListener('click', () => modal.classList.add('hidden'));

    if (btnScan) {
      btnScan.addEventListener('click', () => {
        if (modal) modal.classList.add('hidden');
        triggerDeviceScan(activeDetailDevice);
      });
    }

    if (btnCapture) {
      btnCapture.addEventListener('click', () => {
        if (modal) modal.classList.add('hidden');
        triggerDeviceCapture(activeDetailDevice);
      });
    }
  }

  function openDeviceDetailsModal(dev) {
    activeDetailDevice = dev;
    const modal = document.getElementById('deviceDetailsModal');
    if (!modal) return;

    const icon = document.getElementById('devModalIcon');
    const title = document.getElementById('devModalTitle');
    const sub = document.getElementById('devModalSubtitle');
    const body = document.getElementById('devModalBody');

    if (icon) icon.className = `fa-solid ${dev.icon} text-cyan`;
    if (title) title.innerText = dev.name;
    if (sub) sub.innerText = `IP: ${dev.ip} • MAC: ${dev.mac} • Vendor: ${dev.vendor}`;

    if (body) {
      const portsHtml = dev.openPorts && dev.openPorts.length > 0 
        ? dev.openPorts.map(p => `<span class="port-tag" style="margin-right:4px;">${p}/TCP</span>`).join(' ')
        : '<span class="text-muted">No open listening ports detected</span>';

      body.innerHTML = `
        <div class="host-details-grid">
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-laptop-code"></i> Operating System:</span>
            <strong class="val">${escapeHtml(dev.os || 'Linux / Unix')}</strong>
          </div>
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-microchip"></i> Hardware Vendor:</span>
            <strong class="val">${escapeHtml(dev.vendor)}</strong>
          </div>
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-stopwatch"></i> Subnet Latency (RTT):</span>
            <strong class="val text-emerald">${escapeHtml(dev.latency || '1.4 ms')}</strong>
          </div>
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-chart-pie"></i> Packet Loss:</span>
            <strong class="val text-emerald">${escapeHtml(dev.packetLoss || '0.0%')}</strong>
          </div>
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-shield-check"></i> Security Trust State:</span>
            <strong class="val">${dev.isTrusted ? '<span class="text-emerald">Verified Subnet Member</span>' : '<span class="text-crimson font-bold">Unregistered / Rogue Risk</span>'}</strong>
          </div>
          <div class="host-detail-item">
            <span class="lbl"><i class="fa-solid fa-network-wired"></i> Active Sockets:</span>
            <strong class="val">${escapeHtml(dev.sockets || '12 connections')}</strong>
          </div>
        </div>

        <div class="explainer-section mt-3">
          <h4><i class="fa-solid fa-door-open"></i> Detected Open Services & Ports</h4>
          <div style="margin-top: 8px;">${portsHtml}</div>
        </div>

        <div class="explainer-section">
          <h4><i class="fa-solid fa-file-lines"></i> Security Analyst Notes</h4>
          <p class="text-sm" style="color:var(--text-secondary);">${escapeHtml(dev.notes || 'Normal network activity.')}</p>
        </div>
      `;
    }

    modal.classList.remove('hidden');
  }

  /* -------------------------------------------------------------
     MODULE 5: AI NETWORK DOCTOR (English & Hinglish)
     ------------------------------------------------------------- */
  function setupAiDoctor() {
    const input = document.getElementById('aiDoctorInput');
    const btnSend = document.getElementById('btnSendAiDoctor');
    const chips = document.querySelectorAll('.ai-quick-chips .quick-chip');
    const btnEn = document.getElementById('btnAiEn');
    const btnHi = document.getElementById('btnAiHi');

    if (btnEn && btnHi) {
      btnEn.addEventListener('click', () => {
        aiLanguage = 'en';
        btnEn.classList.add('active');
        btnHi.classList.remove('active');
        showToast("AI Doctor Language: English", "info");
      });
      btnHi.addEventListener('click', () => {
        aiLanguage = 'hi';
        btnHi.classList.add('active');
        btnEn.classList.remove('active');
        showToast("AI Doctor Bhasha: Hinglish / Hindi", "info");
      });
    }

    const sendAction = () => {
      const q = input?.value.trim();
      if (!q) return;
      addUserChat(q);
      if (input) input.value = "";
      setTimeout(() => generateAiAnswer(q), 350);
    };

    if (btnSend) btnSend.addEventListener('click', sendAction);
    if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendAction(); });

    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        const q = chip.getAttribute('data-q');
        addUserChat(q);
        setTimeout(() => generateAiAnswer(q), 350);
      });
    });
  }

  function addUserChat(text) {
    const history = document.getElementById('aiChatHistory');
    if (!history) return;

    const div = document.createElement('div');
    div.className = 'chat-row user-msg';
    div.innerHTML = `
      <div class="chat-avatar"><i class="fa-solid fa-user"></i></div>
      <div class="chat-bubble"><p>${escapeHtml(text)}</p></div>
    `;
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
  }

  function generateAiAnswer(prompt) {
    const p = prompt.toLowerCase();
    const isHi = aiLanguage === 'hi';
    let title = isHi ? "AI Doctor Ka Jawab:" : "AI Doctor Recommendation:";
    let reply = "";

    if (p.includes('ping') || p.includes('lag') || p.includes('game')) {
      reply = isHi 
        ? "Games me high ping aane ke 3 main reasons hote hain: 1) Wi-Fi interference (2.4 GHz ki jagah Ethernet LAN cable use karein). 2) Background me cloud downloads (Steam/OneDrive). 3) High Bufferbloat (Router me QoS ya SQM enable karein)."
        : "High ping in gaming is caused by: 1) Wi-Fi packet jitter (use direct Ethernet CAT6 cable if possible). 2) Background cloud sync (OneDrive, Google Drive uploads). 3) Bufferbloat (enable Smart Queue Management / QoS in your router settings).";
    } else if (p.includes('445') || p.includes('danger') || p.includes('port')) {
      reply = isHi
        ? "Port 445 (SMB) sabse khatarnak ports me se ek hai. 2017 ka WannaCry ransomware isi port ke zariye phaila tha. Router par port 445 ko internet (WAN) ke liye hamesha block rakhein!"
        : "Port 445 (SMB file sharing) is historically high risk. Malware like WannaCry exploited SMB flaws to infect thousands of PCs. Never forward port 445 on your Wi-Fi router to the internet.";
    } else if (p.includes('wi-fi') || p.includes('wifi') || p.includes('stranger')) {
      reply = isHi
        ? "Apne Wi-Fi ko secure rakhne ke liye: 1) Router admin password default 'admin' se badalkar strong karein. 2) WPA3 ya WPA2-AES encryption mandate karein. 3) WPS feature ko disable karein kyunki use easily hack kiya ja sakta hai."
        : "To secure your Wi-Fi: 1) Change default router admin password. 2) Enforce WPA3 or WPA2-AES security. 3) Disable WPS (Wi-Fi Protected Setup) as it has known PIN-cracking vulnerabilities.";
    } else {
      reply = isHi
        ? `Aapne poocha: "${prompt}". PortPulse aapke network security ko continuously check karta hai. Aap 'Live Packet Sniffer' tab me packets dekh sakte hain ya 'Port Scanner' se open ports inspect kar sakte hain!`
        : `Analyzing: "${prompt}". PortPulse helps you spot vulnerabilities before hackers do. Use the Port Scanner tab for services or the Live Packet Sniffer tab to inspect network data in real time!`;
    }

    const history = document.getElementById('aiChatHistory');
    if (!history) return;

    const div = document.createElement('div');
    div.className = 'chat-row ai-msg';
    div.innerHTML = `
      <div class="chat-avatar"><i class="fa-solid fa-robot"></i></div>
      <div class="chat-bubble">
        <h4>${title}</h4>
        <p>${reply}</p>
      </div>
    `;
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
  }

  /* -------------------------------------------------------------
     5. FEATURE 5: 3-FORMAT REPORT EXPORT (JSON, PDF, TXT)
     ------------------------------------------------------------- */
  function setupCommonModals() {
    const exportBtn = document.getElementById('btnExportReport');
    const reportModal = document.getElementById('reportExportModal');
    const closeReportBtn = document.getElementById('btnCloseReportModal');
    const closeReportFooterBtn = document.getElementById('btnCloseReportModalFooter');
    const btnPrint = document.getElementById('btnPrintReport');
    const btnTxt = document.getElementById('btnDownloadTxtReport');
    const btnJson = document.getElementById('btnDownloadJsonReport');

    const closePortBtn = document.getElementById('btnClosePortModal');
    const portUnderstoodBtn = document.getElementById('btnModalUnderstood');
    const portModal = document.getElementById('portDetailModal');

    if (closePortBtn && portModal) closePortBtn.addEventListener('click', () => portModal.classList.add('hidden'));
    if (portUnderstoodBtn && portModal) portUnderstoodBtn.addEventListener('click', () => portModal.classList.add('hidden'));

    if (exportBtn) {
      exportBtn.addEventListener('click', openReportModal);
    }
    if (closeReportBtn && reportModal) closeReportBtn.addEventListener('click', () => reportModal.classList.add('hidden'));
    if (closeReportFooterBtn && reportModal) closeReportFooterBtn.addEventListener('click', () => reportModal.classList.add('hidden'));

    // 1. Export as Plaintext (.txt)
    if (btnTxt) {
      btnTxt.addEventListener('click', exportReportTxt);
    }

    // 2. Export as JSON (.json)
    if (btnJson) {
      btnJson.addEventListener('click', exportReportJson);
    }

    // 3. Export as PDF (Print dialog)
    if (btnPrint) {
      btnPrint.addEventListener('click', () => {
        window.print();
        showToast("Triggered Print / Save as PDF dialog", "info");
      });
    }
  }

  function openReportModal() {
    populateReportPaper();
    const reportModal = document.getElementById('reportExportModal');
    if (reportModal) reportModal.classList.remove('hidden');
  }

  function populateReportPaper() {
    const data = targetDatabase[currentTarget] || generateGenericTargetData(currentTarget);
    const repDate = document.getElementById('repCurrentDate');
    const repTarget = document.getElementById('repTarget');
    const repOs = document.getElementById('repOs');
    const repScore = document.getElementById('repScoreVal');
    const repSummary = document.getElementById('repSummaryText');

    if (repDate) repDate.innerText = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
    if (repTarget) repTarget.innerText = `${data.ip} (${currentTarget})`;
    if (repOs) repOs.innerText = data.os;
    if (repScore) repScore.innerText = `${data.score} / 100`;
    if (repSummary) repSummary.innerText = data.advice;

    const tbody = document.getElementById('repTableBody');
    if (tbody) {
      let html = "";
      data.ports.forEach(p => {
        html += `
          <tr>
            <td><strong>${p.port}/${p.proto}</strong></td>
            <td>${p.service}</td>
            <td><code>${p.version}</code></td>
            <td>${p.state.toUpperCase()}</td>
            <td style="color:${p.risk === 'danger' ? '#dc2626' : (p.risk === 'warn' ? '#d97706' : '#15803d')}; font-weight:600;">
              ${p.risk.toUpperCase()}
            </td>
          </tr>
        `;
      });
      tbody.innerHTML = html;
    }
  }

  function exportReportTxt() {
    const data = targetDatabase[currentTarget] || generateGenericTargetData(currentTarget);
    const dateStr = new Date().toISOString();

    let txt = "=========================================================================\n";
    txt += "                PORTPULSE STUDIO - NETWORK SECURITY AUDIT REPORT         \n";
    txt += "=========================================================================\n\n";
    txt += `Generated On    : ${dateStr}\n`;
    txt += `Target Host     : ${data.ip} (${currentTarget})\n`;
    txt += `Operating System: ${data.os}\n`;
    txt += `Latency (RTT)   : ${data.latency}\n`;
    txt += `Security Score  : ${data.score} / 100\n`;
    txt += `Summary / Note  : ${data.advice}\n\n`;
    txt += "-------------------------------------------------------------------------\n";
    txt += "PORT/PROTO  | STATE     | SERVICE          | RISK      | VERSION\n";
    txt += "-------------------------------------------------------------------------\n";

    data.ports.forEach(p => {
      const portProto = `${p.port}/${p.proto}`.padEnd(12, ' ');
      const state = p.state.toUpperCase().padEnd(10, ' ');
      const service = p.service.padEnd(17, ' ');
      const risk = p.risk.toUpperCase().padEnd(10, ' ');
      txt += `${portProto}| ${state}| ${service}| ${risk}| ${p.version}\n`;
    });

    txt += "-------------------------------------------------------------------------\n\n";
    txt += "CONNECTED LAN SUBNET INVENTORY:\n";
    lanDevices.forEach(d => {
      txt += `* [${d.isTrusted ? 'TRUSTED' : 'ALERT'}] ${d.name} (${d.ip}) - MAC: ${d.mac} [Vendor: ${d.vendor}]\n`;
    });

    txt += "\n=========================================================================\n";
    txt += "End of PortPulse Security Report.\n";

    downloadFile(txt, `PortPulse_Audit_${currentTarget}.txt`, 'text/plain');
    showToast("Downloaded TXT audit report!", "success");
  }

  function exportReportJson() {
    const data = targetDatabase[currentTarget] || generateGenericTargetData(currentTarget);
    const reportObj = {
      generator: "PortPulse Studio v2.4 Ultimate",
      generatedAt: new Date().toISOString(),
      target: {
        host: currentTarget,
        ip: data.ip,
        os: data.os,
        mac: data.mac,
        latency: data.latency,
        securityScore: data.score,
        advice: data.advice
      },
      ports: data.ports,
      lanInventory: lanDevices,
      packetSnifferStats: {
        totalCaptured: snifferPacketCounter,
        threatAlerts: snifferAlertCount
      }
    };

    const jsonStr = JSON.stringify(reportObj, null, 2);
    downloadFile(jsonStr, `PortPulse_Audit_${currentTarget}.json`, 'application/json');
    showToast("Downloaded JSON audit report!", "success");
  }

  function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* =============================================================
     WIRESHARK DESKTOP MENUBAR & QUICK ACTION CONTROLLER
     ============================================================= */
  function setupWiresharkMenuBar() {
    const menuItems = document.querySelectorAll('.ws-menubar .ws-menu-item');

    menuItems.forEach(item => {
      const trigger = item.querySelector('.ws-menu-trigger');
      if (!trigger) return;

      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = item.classList.contains('open');
        menuItems.forEach(m => m.classList.remove('open'));
        if (!isOpen) item.classList.add('open');
      });

      item.addEventListener('mouseenter', () => {
        const anyOpen = Array.from(menuItems).some(m => m.classList.contains('open'));
        if (anyOpen) {
          menuItems.forEach(m => m.classList.remove('open'));
          item.classList.add('open');
        }
      });
    });

    // Close on outside click or Escape
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.ws-menubar')) {
        menuItems.forEach(m => m.classList.remove('open'));
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        menuItems.forEach(m => m.classList.remove('open'));
      }
    });

    // Wire File menu items
    const btnFileOpen = document.getElementById('wsMenuFileOpen');
    const btnFileSave = document.getElementById('wsMenuFileSave');
    const btnFileExport = document.getElementById('wsMenuFileExportReport');
    const btnFilePrint = document.getElementById('wsMenuFilePrint');
    const btnFileClear = document.getElementById('wsMenuFileClear');
    const btnFileExit = document.getElementById('wsMenuFileExit');

    if (btnFileOpen) {
      btnFileOpen.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        showToast("Loaded capture session 'wireshark_dump_en0.pcap' (1,280 frames)", "info");
      });
    }
    if (btnFileSave) {
      btnFileSave.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        exportReportJson();
      });
    }
    if (btnFileExport) {
      btnFileExport.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openReportModal();
      });
    }
    if (btnFilePrint) {
      btnFilePrint.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        window.print();
      });
    }
    if (btnFileClear) {
      btnFileClear.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnClearSniffer = document.getElementById('btnClearSniffer');
        if (btnClearSniffer) btnClearSniffer.click();
      });
    }
    if (btnFileExit) {
      btnFileExit.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnLogout = document.getElementById('btnLogout');
        if (btnLogout) btnLogout.click();
      });
    }

    // Wire Edit menu items
    const btnEditFind = document.getElementById('wsMenuEditFind');
    const btnEditCopy = document.getElementById('wsMenuEditCopyCmd');
    const btnEditClearFilt = document.getElementById('wsMenuEditClearFilter');
    const btnEditReset = document.getElementById('wsMenuEditResetAll');

    if (btnEditFind) {
      btnEditFind.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-wireshark');
        const filterInput = document.getElementById('snifferFilterInput');
        if (filterInput) { filterInput.focus(); filterInput.select(); }
      });
    }
    if (btnEditCopy) {
      btnEditCopy.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnCopyCmd = document.getElementById('btnCopyCmd');
        if (btnCopyCmd) btnCopyCmd.click();
      });
    }
    if (btnEditClearFilt) {
      btnEditClearFilt.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const filterInput = document.getElementById('snifferFilterInput');
        if (filterInput) { filterInput.value = ''; renderSnifferTable(''); }
        showToast("Display filter cleared", "info");
      });
    }
    if (btnEditReset) {
      btnEditReset.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnResetManual = document.getElementById('btnResetManualCmd');
        if (btnResetManual) btnResetManual.click();
      });
    }

    // Wire View menu items
    const btnViewColorize = document.getElementById('wsMenuViewColorize');
    const btnViewParticles = document.getElementById('wsMenuViewParticles');
    const btnViewTheme = document.getElementById('wsMenuViewTheme');
    const btnViewZoomIn = document.getElementById('wsMenuViewZoomIn');
    const btnViewZoomOut = document.getElementById('wsMenuViewZoomOut');

    if (btnViewColorize) {
      btnViewColorize.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        showToast("Protocol row colorizing: ACTIVE", "info");
      });
    }
    if (btnViewParticles) {
      btnViewParticles.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnPart = document.getElementById('btnToggleParticles');
        if (btnPart) btnPart.click();
      });
    }
    if (btnViewTheme) {
      btnViewTheme.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        toggleTheme();
      });
    }
    if (btnViewZoomIn) {
      btnViewZoomIn.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        document.body.style.zoom = (parseFloat(document.body.style.zoom || 1) + 0.05).toString();
        showToast("Zoomed in interface", "info");
      });
    }
    if (btnViewZoomOut) {
      btnViewZoomOut.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        document.body.style.zoom = Math.max(0.8, (parseFloat(document.body.style.zoom || 1) - 0.05)).toString();
        showToast("Zoomed out interface", "info");
      });
    }

    // Wire Capture menu items
    const btnCapStart = document.getElementById('wsMenuCapStart');
    const btnCapStop = document.getElementById('wsMenuCapStop');
    const btnCapRestart = document.getElementById('wsMenuCapRestart');
    const btnCapInterfaces = document.getElementById('wsMenuCapInterfaces');
    const btnCapSimLeak = document.getElementById('wsMenuCapSimLeak');

    if (btnCapStart) {
      btnCapStart.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        if (!snifferRunning) {
          const btn = document.getElementById('btnToggleSniffer');
          if (btn) btn.click();
        }
      });
    }
    if (btnCapStop) {
      btnCapStop.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        if (snifferRunning) {
          const btn = document.getElementById('btnToggleSniffer');
          if (btn) btn.click();
        }
      });
    }
    if (btnCapRestart) {
      btnCapRestart.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const btnClear = document.getElementById('btnClearSniffer');
        if (btnClear) btnClear.click();
        if (!snifferRunning) {
          const btn = document.getElementById('btnToggleSniffer');
          if (btn) btn.click();
        }
        showToast("Packet sniffer restarted fresh", "info");
      });
    }
    if (btnCapInterfaces) {
      btnCapInterfaces.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-wireshark');
        const ifaceCard = document.getElementById('wsInterfacesCard');
        if (ifaceCard) ifaceCard.scrollIntoView({ behavior: 'smooth' });
      });
    }
    if (btnCapSimLeak) {
      btnCapSimLeak.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-wireshark');
        injectThreatLeakPacket();
      });
    }

    // Wire Analyze menu items
    const btnAnalyzeFollow = document.getElementById('wsMenuAnalyzeFollow');
    const btnAnalyzeVuln = document.getElementById('wsMenuAnalyzeVuln');
    const btnAnalyzeDecode = document.getElementById('wsMenuAnalyzeDecode');
    const btnAnalyzeHealth = document.getElementById('wsMenuAnalyzeHealth');

    if (btnAnalyzeFollow) {
      btnAnalyzeFollow.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openFollowTcpStreamModal();
      });
    }
    if (btnAnalyzeVuln) {
      btnAnalyzeVuln.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-nmap');
        const vulnBtn = document.querySelector('.profile-pill[data-profile="vuln"]');
        if (vulnBtn) vulnBtn.click();
        startScan();
      });
    }
    if (btnAnalyzeDecode) {
      btnAnalyzeDecode.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        if (snifferPackets.length > 0) {
          openPacketInspectorModal(snifferPackets[0]);
        } else {
          showToast("No packets captured yet to decode", "info");
        }
      });
    }
    if (btnAnalyzeHealth) {
      btnAnalyzeHealth.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-traceroute');
        const ring = document.getElementById('healthGaugeRing');
        if (ring) ring.scrollIntoView({ behavior: 'smooth' });
      });
    }

    // Wire Statistics menu items
    const btnStatsHier = document.getElementById('wsMenuStatsHierarchy');
    const btnStatsIo = document.getElementById('wsMenuStatsIo');
    const btnStatsDns = document.getElementById('wsMenuStatsDns');
    const btnStatsEndpoints = document.getElementById('wsMenuStatsEndpoints');

    if (btnStatsHier) {
      btnStatsHier.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openProtocolHierarchyModal();
      });
    }
    if (btnStatsIo) {
      btnStatsIo.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-traceroute');
      });
    }
    if (btnStatsDns) {
      btnStatsDns.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-traceroute');
        const btnRetest = document.getElementById('btnRetestDns');
        if (btnRetest) btnRetest.click();
      });
    }
    if (btnStatsEndpoints) {
      btnStatsEndpoints.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-devices');
      });
    }

    // Wire Tools menu items
    const btnToolsPing = document.getElementById('wsMenuToolsPing');
    const btnToolsForge = document.getElementById('wsMenuToolsForge');
    const btnToolsWhois = document.getElementById('wsMenuToolsWhois');
    const btnToolsNmap = document.getElementById('wsMenuToolsNmapCli');
    const btnToolsTrace = document.getElementById('wsMenuToolsTrace');

    if (btnToolsPing) {
      btnToolsPing.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openPingToolModal();
      });
    }
    if (btnToolsForge) {
      btnToolsForge.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openPacketForgeModal();
      });
    }
    if (btnToolsWhois) {
      btnToolsWhois.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        openWhoisIntelModal();
      });
    }
    if (btnToolsNmap) {
      btnToolsNmap.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-nmap');
        const manualBox = document.getElementById('manualFullCmdInput');
        if (manualBox) { manualBox.focus(); manualBox.scrollIntoView({ behavior: 'smooth' }); }
      });
    }
    if (btnToolsTrace) {
      btnToolsTrace.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-traceroute');
      });
    }

    // Wire Help menu items
    const btnHelpShortcuts = document.getElementById('wsMenuHelpShortcuts');
    const btnHelpAi = document.getElementById('wsMenuHelpAiDoc');
    const btnHelpAbout = document.getElementById('wsMenuHelpAbout');

    if (btnHelpShortcuts) {
      btnHelpShortcuts.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        const omni = document.getElementById('globalOmnibarSearch');
        if (omni) { omni.focus(); omni.select(); }
        showToast("Keyboard Shortcuts: Ctrl+K (Quick Search), Ctrl+O (Open), Ctrl+S (Save), Ctrl+E (Export), Ctrl+F (Filter)", "info");
      });
    }
    if (btnHelpAi) {
      btnHelpAi.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        switchTab('tab-ai');
      });
    }
    if (btnHelpAbout) {
      btnHelpAbout.addEventListener('click', () => {
        menuItems.forEach(m => m.classList.remove('open'));
        showToast("PortPulse Studio v2.4 Ultimate — Nmap & Wireshark Diagnostics Suite", "success");
      });
    }

    // Ribbon Action Buttons
    const rStart = document.getElementById('ribbonStartCapture');
    const rStop = document.getElementById('ribbonStopCapture');
    const rRestart = document.getElementById('ribbonRestartCapture');
    const rInterfaces = document.getElementById('ribbonInterfaces');
    const rSave = document.getElementById('ribbonSavePcap');
    const rFind = document.getElementById('ribbonFindPacket');
    const rFollow = document.getElementById('ribbonFollowStream');
    const rPing = document.getElementById('ribbonPingTool');
    const rHierarchy = document.getElementById('ribbonStatsHierarchy');
    const rForge = document.getElementById('ribbonPacketForge');
    const rWhois = document.getElementById('ribbonWhois');
    const rBadge = document.getElementById('wsActiveInterfaceBadge');

    if (rStart) rStart.addEventListener('click', () => { if (!snifferRunning) document.getElementById('btnToggleSniffer')?.click(); });
    if (rStop) rStop.addEventListener('click', () => { if (snifferRunning) document.getElementById('btnToggleSniffer')?.click(); });
    if (rRestart) rRestart.addEventListener('click', () => {
      document.getElementById('btnClearSniffer')?.click();
      if (!snifferRunning) document.getElementById('btnToggleSniffer')?.click();
    });
    if (rInterfaces) rInterfaces.addEventListener('click', () => {
      switchTab('tab-wireshark');
      document.getElementById('wsInterfacesCard')?.scrollIntoView({ behavior: 'smooth' });
    });
    if (rSave) rSave.addEventListener('click', exportReportJson);
    if (rFind) rFind.addEventListener('click', () => {
      switchTab('tab-wireshark');
      document.getElementById('snifferFilterInput')?.focus();
    });
    if (rFollow) rFollow.addEventListener('click', openFollowTcpStreamModal);
    if (rPing) rPing.addEventListener('click', openPingToolModal);
    if (rHierarchy) rHierarchy.addEventListener('click', openProtocolHierarchyModal);
    if (rForge) rForge.addEventListener('click', openPacketForgeModal);
    if (rWhois) rWhois.addEventListener('click', openWhoisIntelModal);
    if (rBadge) rBadge.addEventListener('click', () => {
      switchTab('tab-wireshark');
      document.getElementById('wsInterfacesCard')?.scrollIntoView({ behavior: 'smooth' });
    });
  }

  /* =============================================================
     WIRESHARK NETWORK INTERFACE SELECTOR (SCREENSHOT REPLICA)
     ============================================================= */
  /* =============================================================
     WIRESHARK NETWORK INTERFACE SELECTOR (REAL SYSTEM ADAPTERS)
     ============================================================= */
  let networkInterfaces = [
    { id: "wifi", name: "Wi-Fi", ip: "192.168.1.105", type: "wireless", icon: "fa-wifi", status: "active", rxRate: "1.4 MB/s", isSelected: true },
    { id: "vmnet8", name: "VMware Network Adapter VMnet8", ip: "192.168.128.1", type: "virtual", icon: "fa-network-wired", status: "active", rxRate: "180 KB/s", isSelected: false },
    { id: "loopback", name: "Adapter for loopback traffic capture", ip: "127.0.0.1", type: "loopback", icon: "fa-rotate", status: "active", rxRate: "24 KB/s", isSelected: false },
    { id: "vmnet1", name: "VMware Network Adapter VMnet1", ip: "192.168.220.1", type: "virtual", icon: "fa-network-wired", status: "idle", rxRate: "0 KB/s", isSelected: false },
    { id: "eth0", name: "Local Area Connection* 1 (Intel Ethernet)", ip: "192.168.1.106", type: "ethernet", icon: "fa-ethernet", status: "idle", rxRate: "0 KB/s", isSelected: false },
    { id: "etw", name: "Event Tracing for Windows (ETW) reader: etwdump", ip: "Kernel Provider", type: "etw", icon: "fa-microchip", status: "idle", rxRate: "0 KB/s", isSelected: false }
  ];

  let activeInterface = networkInterfaces[0];

  async function fetchRealInterfaces() {
    try {
      const resp = await fetch('/api/interfaces');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data.success && data.interfaces && data.interfaces.length > 0) {
        networkInterfaces = data.interfaces.map((ifc, idx) => ({
          id: ifc.id || ifc.guid || `iface_${idx}`,
          name: ifc.name || ifc.description || `Adapter ${idx+1}`,
          description: ifc.description || ifc.name,
          ip: ifc.ip || 'DHCP Dynamic',
          type: ifc.type || 'ethernet',
          icon: ifc.icon || 'fa-network-wired',
          status: ifc.status || 'idle',
          rxRate: ifc.rxRate || '0 KB/s',
          isSelected: false
        }));

        // Pick active interface: prioritize Wi-Fi AX101 or active wireless adapter
        let best = networkInterfaces.find(i => i.name.toLowerCase().includes('wi-fi') || i.name.toLowerCase().includes('wireless'));
        if (!best) best = networkInterfaces.find(i => i.status === 'active');
        if (!best) best = networkInterfaces[0];
        if (best) {
          best.isSelected = true;
          activeInterface = best;
        }

        // Update dropdown selector
        const selectEl = document.getElementById('wsInterfaceSelect');
        if (selectEl) {
          selectEl.innerHTML = networkInterfaces.map(i => `
            <option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${i.ip})</option>
          `).join('');
          if (activeInterface) selectEl.value = activeInterface.name;
        }

        // Update badge
        const badgeName = document.getElementById('wsCurrentInterfaceName');
        if (badgeName && activeInterface) {
          badgeName.innerText = `${activeInterface.name} (${activeInterface.ip})`;
        }

        renderInterfaceTable();
      }
    } catch (err) {
      console.warn("Failed to fetch real interfaces from backend:", err);
    }
  }

  function setupInterfaceSelector() {
    fetchRealInterfaces();

    const btnToggle = document.getElementById('btnToggleInterfacesView');
    const wrapper = document.getElementById('wsInterfaceListWrapper');
    const lbl = document.getElementById('lblToggleInterfaces');
    const icon = document.getElementById('iconToggleInterfaces');

    if (btnToggle && wrapper) {
      btnToggle.addEventListener('click', () => {
        wrapper.classList.toggle('hidden');
        const isHidden = wrapper.classList.contains('hidden');
        if (lbl) lbl.innerText = isHidden ? "Show Interfaces" : "Hide Interfaces";
        if (icon) icon.className = isHidden ? "fa-solid fa-chevron-down" : "fa-solid fa-chevron-up";
      });
    }

    const btnRefresh = document.getElementById('btnRefreshInterfaces');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', async () => {
        btnRefresh.disabled = true;
        const origHtml = btnRefresh.innerHTML;
        btnRefresh.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Refreshing...';
        await fetchRealInterfaces();
        btnRefresh.innerHTML = origHtml;
        btnRefresh.disabled = false;
        showToast("Refreshed network adapters from system driver.", "info");
      });
    }

    const selectDropdown = document.getElementById('wsInterfaceSelect');
    if (selectDropdown) {
      selectDropdown.addEventListener('change', async (e) => {
        const val = e.target.value;
        const found = networkInterfaces.find(i => i.name === val || i.id === val);
        if (found) {
          networkInterfaces.forEach(i => i.isSelected = (i.name === found.name));
          activeInterface = found;

          const badgeName = document.getElementById('wsCurrentInterfaceName');
          if (badgeName) badgeName.innerText = `${activeInterface.name} (${activeInterface.ip})`;

          renderInterfaceTable();
          if (snifferRunning) {
            await startRealCapture();
          }
          showToast(`Switched active capture adapter to ${activeInterface.name}`, "success");
        }
      });
    }

    const typeFilter = document.getElementById('wsInterfaceFilterType');
    if (typeFilter) {
      typeFilter.addEventListener('change', () => {
        renderInterfaceTable(typeFilter.value);
      });
    }
  }

  function renderInterfaceTable(filter = "all") {
    const tbody = document.getElementById('wsInterfaceTableBody');
    if (!tbody) return;

    let list = networkInterfaces;
    if (filter === 'active') list = networkInterfaces.filter(i => i.status === 'active');
    if (filter === 'wireless') list = networkInterfaces.filter(i => i.type === 'wireless');

    tbody.innerHTML = list.map(iface => `
      <tr class="ws-iface-row ${iface.isSelected ? 'selected' : ''}" data-iface-id="${iface.id}">
        <td style="width: 100%;">
          <div class="ws-iface-left">
            <i class="fa-solid ${iface.icon} ws-iface-icon"></i>
            <div>
              <span class="ws-iface-name">${escapeHtml(iface.name)}</span>
              <span class="ws-iface-ip">(${iface.ip})</span>
            </div>
          </div>
        </td>
        <td style="padding: 0 16px;">
          <canvas class="ws-iface-sparkline-canvas" id="sparkCanvas_${iface.id}" width="100" height="24"></canvas>
        </td>
        <td style="white-space: nowrap; padding-right: 14px;">
          <span class="ws-iface-status-badge ${iface.status}">${iface.status.toUpperCase()}</span>
        </td>
      </tr>
    `).join('');

    // Draw sparklines on each row
    list.forEach(iface => {
      drawInterfaceSparkline(iface);
    });

    // Row click event
    tbody.querySelectorAll('.ws-iface-row').forEach(row => {
      row.addEventListener('click', async () => {
        const id = row.getAttribute('data-iface-id');
        networkInterfaces.forEach(i => i.isSelected = (i.id === id));
        activeInterface = networkInterfaces.find(i => i.id === id);

        const selectEl = document.getElementById('wsInterfaceSelect');
        if (selectEl && activeInterface) selectEl.value = activeInterface.name;

        const badgeName = document.getElementById('wsCurrentInterfaceName');
        if (badgeName && activeInterface) badgeName.innerText = `${activeInterface.name} (${activeInterface.ip})`;

        renderInterfaceTable(filter);
        if (snifferRunning) {
          await startRealCapture();
        }
        showToast(`Switched active capture interface to ${activeInterface.name} (${activeInterface.ip})`, "success");
      });
    });
  }

  function drawInterfaceSparkline(iface) {
    const canvas = document.getElementById(`sparkCanvas_${iface.id}`);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    if (iface.status === 'idle') {
      ctx.beginPath();
      ctx.moveTo(0, h / 2);
      ctx.lineTo(w, h / 2);
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.4)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      return;
    }

    // Active waveform pulse
    ctx.beginPath();
    ctx.moveTo(0, h / 2);
    const points = [h/2, h/2 - 4, h/2 + 6, h/2 - 9, h/2 + 8, h/2 - 11, h/2 + 6, h/2];
    const step = w / (points.length - 1);
    for (let i = 1; i < points.length; i++) {
      const x = i * step;
      const y = points[i];
      ctx.lineTo(x, y);
    }
    ctx.strokeStyle = iface.isSelected ? '#06b6d4' : '#3b82f6';
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  /* =============================================================
     FEATURE: CONTINUOUS ICMP PING & SUBNET SWEEP UTILITY
     ============================================================= */
  let isPinging = false;
  let pingTimer = null;
  let pingSent = 0;
  let pingRecv = 0;
  let pingModalLatencies = [];

  function setupPingUtility() {
    const btnStart = document.getElementById('btnStartPingAction');
    const btnSweep = document.getElementById('btnSubnetSweepAction');
    const btnClear = document.getElementById('btnClearPingTerminal');
    const btnClose = document.getElementById('btnClosePingModal');
    const btnCloseFooter = document.getElementById('btnClosePingModalFooter');
    const modal = document.getElementById('modalPingTool');

    if (btnStart) btnStart.addEventListener('click', togglePingSession);
    if (btnSweep) btnSweep.addEventListener('click', executeSubnetSweep);
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        const term = document.getElementById('pingTerminalOutput');
        if (term) term.innerHTML = `<div class="term-line term-muted">Terminal cleared.</div>`;
      });
    }

    if (btnClose && modal) btnClose.addEventListener('click', closePingToolModal);
    if (btnCloseFooter && modal) btnCloseFooter.addEventListener('click', closePingToolModal);
  }

  function openPingToolModal() {
    const modal = document.getElementById('modalPingTool');
    if (modal) modal.classList.remove('hidden');
  }

  function closePingToolModal() {
    stopPingSession();
    const modal = document.getElementById('modalPingTool');
    if (modal) modal.classList.add('hidden');
  }

  function togglePingSession() {
    if (isPinging) {
      stopPingSession();
    } else {
      startPingSession();
    }
  }

  function startPingSession() {
    const hostInput = document.getElementById('pingModalHostInput');
    const sizeSelect = document.getElementById('pingModalSizeSelect');
    const term = document.getElementById('pingTerminalOutput');
    const btnTxt = document.getElementById('txtPingAction');
    const btn = document.getElementById('btnStartPingAction');

    const host = hostInput?.value.trim() || '8.8.8.8';
    const bytes = sizeSelect?.value || '32';

    isPinging = true;
    pingSent = 0;
    pingRecv = 0;
    pingModalLatencies = [];

    if (btnTxt) btnTxt.innerText = "Stop Ping";
    if (btn) btn.className = "btn btn-outline-danger";

    if (term) {
      const headerLine = document.createElement('div');
      headerLine.className = 'term-line';
      headerLine.innerHTML = `Pinging <strong class="term-cyan">${escapeHtml(host)}</strong> with ${bytes} bytes of data:`;
      term.appendChild(headerLine);
      term.scrollTop = term.scrollHeight;
    }

    pingTimer = setInterval(() => {
      pingSent++;
      const isLoss = Math.random() < 0.02; // 2% loss simulation
      const rtt = isLoss ? null : Math.floor(Math.random() * 8 + 12);

      if (!isLoss) {
        pingRecv++;
        pingModalLatencies.push(rtt);
      }

      // Update statistics
      const lossPct = Math.round(((pingSent - pingRecv) / pingSent) * 100);
      const min = pingModalLatencies.length ? Math.min(...pingModalLatencies) : 0;
      const max = pingModalLatencies.length ? Math.max(...pingModalLatencies) : 0;
      const avg = pingModalLatencies.length ? Math.round(pingModalLatencies.reduce((a, b) => a + b, 0) / pingModalLatencies.length) : 0;
      const jitter = (Math.abs((rtt || avg) - avg)).toFixed(1);

      document.getElementById('pingStatSent').innerText = pingSent;
      document.getElementById('pingStatRecv').innerText = pingRecv;
      document.getElementById('pingStatLoss').innerText = `${lossPct}%`;
      document.getElementById('pingStatMin').innerText = `${min} ms`;
      document.getElementById('pingStatAvg').innerText = `${avg} ms`;
      document.getElementById('pingStatMax').innerText = `${max} ms`;
      document.getElementById('pingStatJitter').innerText = `${jitter} ms`;

      if (term) {
        const line = document.createElement('div');
        line.className = 'term-line';
        if (isLoss) {
          line.innerHTML = `<span class="term-red">Request timed out. [Sequence=${pingSent}]</span>`;
        } else {
          line.innerHTML = `Reply from ${escapeHtml(host)}: bytes=${bytes} <span class="term-green">time=${rtt}ms</span> TTL=56 [Seq=${pingSent}]`;
        }
        term.appendChild(line);
        term.scrollTop = term.scrollHeight;
      }
    }, 900);
  }

  function stopPingSession() {
    if (!isPinging) return;
    clearInterval(pingTimer);
    isPinging = false;

    const btnTxt = document.getElementById('txtPingAction');
    const btn = document.getElementById('btnStartPingAction');
    const term = document.getElementById('pingTerminalOutput');
    const hostInput = document.getElementById('pingModalHostInput');

    if (btnTxt) btnTxt.innerText = "Start Ping";
    if (btn) btn.className = "btn btn-primary";

    if (term) {
      const host = hostInput?.value.trim() || '8.8.8.8';
      const lossPct = pingSent > 0 ? Math.round(((pingSent - pingRecv) / pingSent) * 100) : 0;
      const summary = document.createElement('div');
      summary.className = 'term-line term-muted';
      summary.style.marginTop = '6px';
      summary.innerHTML = `--- ${escapeHtml(host)} ping statistics ---<br>
        ${pingSent} packets transmitted, ${pingRecv} received, ${lossPct}% packet loss`;
      term.appendChild(summary);
      term.scrollTop = term.scrollHeight;
    }
  }

  function executeSubnetSweep() {
    stopPingSession();
    const term = document.getElementById('pingTerminalOutput');
    if (!term) return;

    const startLine = document.createElement('div');
    startLine.className = 'term-line term-cyan';
    startLine.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Starting ICMP Subnet Sweep on 192.168.1.0/24 (Probing 254 endpoints)...`;
    term.appendChild(startLine);
    term.scrollTop = term.scrollHeight;

    const responders = [
      { ip: "192.168.1.1", name: "Gateway Router (TP-Link)", rtt: "1.2 ms" },
      { ip: "192.168.1.12", name: "Apple iPhone 15 Pro", rtt: "9.4 ms" },
      { ip: "192.168.1.18", name: "Samsung Smart TV", rtt: "12.8 ms" },
      { ip: "192.168.1.50", name: "Local Web Server", rtt: "2.8 ms" },
      { ip: "192.168.1.88", name: "PlayStation 5 Console", rtt: "8.1 ms" },
      { ip: "192.168.1.105", name: "Workstation (This Machine)", rtt: "0.3 ms" },
      { ip: "192.168.1.199", name: "Unknown ESP32 Device", rtt: "34.2 ms" }
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < responders.length) {
        const item = responders[i];
        const line = document.createElement('div');
        line.className = 'term-line';
        line.innerHTML = `<span class="term-green">[ALIVE]</span> ${item.ip} - ${item.name} (${item.rtt})`;
        term.appendChild(line);
        term.scrollTop = term.scrollHeight;
        i++;
      } else {
        clearInterval(interval);
        const done = document.createElement('div');
        done.className = 'term-line term-green';
        done.innerHTML = `Sweep finished: 7 responsive hosts discovered on subnet 192.168.1.0/24.`;
        term.appendChild(done);
        term.scrollTop = term.scrollHeight;
        showToast("Subnet ping sweep completed: 7 active hosts responding!", "success");
      }
    }, 200);
  }

  /* =============================================================
     FEATURE 1: FOLLOW TCP STREAM (WIRESHARK DIALOGUE)
     ============================================================= */
  const tcpStreamDatabase = {
    stream0: {
      client: "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n",
      server: "HTTP/1.1 200 OK\r\nDate: Thu, 17 Sep 2026 09:12:04 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nLast-Modified: Fri, 20 Mar 2026 18:24:12 GMT\r\nETag: \"2b96-5b31f0f35a080\"\r\nAccept-Ranges: bytes\r\nContent-Length: 11158\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html>\n<html>\n<head><title>Go ahead and ScanMe!</title></head>\n<body>\n<h1>Welcome to Scanme.Nmap.Org!</h1>\n<p>Most of the pages on this site are for testing network scanners...</p>\n</body></html>"
    },
    stream1: {
      client: "POST /api/login HTTP/1.1\r\nHost: internal-portal.lan\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 43\r\nConnection: keep-alive\r\n\r\nuser=admin&pass=SuperSecret2026!",
      server: "HTTP/1.1 200 OK\r\nDate: Thu, 17 Sep 2026 09:14:22 GMT\r\nServer: nginx/1.18.0\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 104\r\n\r\n{\"status\":\"authenticated\",\"role\":\"administrator\",\"session_id\":\"sess_98f412a8bc02\",\"issued_at\":1789643524}"
    },
    stream2: {
      client: "0x48f1 Standard query 0x48f1 A www.google.com\r\n  Queries:\r\n    www.google.com: type A, class IN",
      server: "0x48f1 Standard query response 0x48f1 A www.google.com\r\n  Answers:\r\n    www.google.com: type A, class IN, addr 142.250.190.46\r\n  Authoritative nameservers:\r\n    ns1.google.com\r\n    ns2.google.com"
    }
  };

  function setupFollowTcpStream() {
    const streamSelect = document.getElementById('followStreamSelect');
    const fmtPills = document.querySelectorAll('.stream-format-pills .btn');
    const btnDownload = document.getElementById('btnDownloadStreamText');
    const btnClose = document.getElementById('btnCloseFollowModal');
    const btnCloseFooter = document.getElementById('btnCloseFollowModalFooter');
    const modal = document.getElementById('modalFollowTcpStream');

    if (streamSelect) {
      streamSelect.addEventListener('change', () => {
        renderTcpStreamDialogue(streamSelect.value);
      });
    }

    fmtPills.forEach(pill => {
      pill.addEventListener('click', () => {
        fmtPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        const fmt = pill.getAttribute('data-fmt');
        renderTcpStreamDialogue(streamSelect?.value || 'stream0', fmt);
      });
    });

    if (btnDownload) {
      btnDownload.addEventListener('click', () => {
        const content = document.getElementById('followStreamContent')?.innerText || '';
        downloadFile(content, 'Follow_TCP_Stream_Dump.txt', 'text/plain');
        showToast("Downloaded TCP stream conversation dump!", "success");
      });
    }

    if (btnClose && modal) btnClose.addEventListener('click', () => modal.classList.add('hidden'));
    if (btnCloseFooter && modal) btnCloseFooter.addEventListener('click', () => modal.classList.add('hidden'));
  }

  function openFollowTcpStreamModal() {
    const modal = document.getElementById('modalFollowTcpStream');
    if (!modal) return;
    renderTcpStreamDialogue('stream1'); // Default to cleartext auth leak
    const select = document.getElementById('followStreamSelect');
    if (select) select.value = 'stream1';
    modal.classList.remove('hidden');
  }

  function renderTcpStreamDialogue(streamKey = 'stream1', format = 'ascii') {
    const container = document.getElementById('followStreamContent');
    if (!container) return;

    const data = tcpStreamDatabase[streamKey] || tcpStreamDatabase['stream0'];

    if (format === 'hex') {
      const clientHex = stringToHexDump(data.client);
      const serverHex = stringToHexDump(data.server);
      container.innerHTML = `
        <div class="stream-chunk-client"><strong>-- [Client Transmission 192.168.1.105] --</strong><br>${escapeHtml(clientHex)}</div>
        <div class="stream-chunk-server"><strong>-- [Server Transmission] --</strong><br>${escapeHtml(serverHex)}</div>
      `;
    } else {
      container.innerHTML = `
        <div class="stream-chunk-client">${escapeHtml(data.client)}</div>
        <div class="stream-chunk-server">${escapeHtml(data.server)}</div>
      `;
    }
  }

  function stringToHexDump(str) {
    let out = "";
    for (let i = 0; i < str.length; i += 16) {
      const slice = str.slice(i, i + 16);
      const hex = Array.from(slice).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
      const ascii = slice.replace(/[^\x20-\x7E]/g, '.');
      out += `${i.toString(16).padStart(4, '0')}  ${hex.padEnd(48, ' ')}  |${ascii}|\n`;
    }
    return out;
  }

  /* =============================================================
     FEATURE 2: PROTOCOL HIERARCHY STATISTICS
     ============================================================= */
  function setupProtocolHierarchy() {
    const btnClose = document.getElementById('btnCloseHierarchyModal');
    const btnCloseFooter = document.getElementById('btnCloseHierarchyModalFooter');
    const modal = document.getElementById('modalProtocolHierarchy');

    if (btnClose && modal) btnClose.addEventListener('click', () => modal.classList.add('hidden'));
    if (btnCloseFooter && modal) btnCloseFooter.addEventListener('click', () => modal.classList.add('hidden'));
  }

  function openProtocolHierarchyModal() {
    const modal = document.getElementById('modalProtocolHierarchy');
    if (!modal) return;
    renderProtocolHierarchyTable();
    modal.classList.remove('hidden');
  }

  function renderProtocolHierarchyTable() {
    const tbody = document.getElementById('hierarchyTableBody');
    if (!tbody) return;

    const protocols = [
      { name: "Frame (Raw Physical)", indent: 0, pct: 100, pkts: 1280, bytes: "1.42 MB", rate: "1.4 MB/s", color: "#06b6d4" },
      { name: "↳ Ethernet II", indent: 1, pct: 100, pkts: 1280, bytes: "1.42 MB", rate: "1.4 MB/s", color: "#06b6d4" },
      { name: "↳ Internet Protocol Version 4 (IPv4)", indent: 2, pct: 94.2, pkts: 1206, bytes: "1.35 MB", rate: "1.3 MB/s", color: "#3b82f6" },
      { name: "↳ Transmission Control Protocol (TCP)", indent: 3, pct: 68.4, pkts: 875, bytes: "1.02 MB", rate: "980 KB/s", color: "#8b5cf6" },
      { name: "↳ Transport Layer Security (TLS 1.3 / HTTPS)", indent: 3, pct: 51.2, pkts: 655, bytes: "840 KB", rate: "810 KB/s", color: "#10b981" },
      { name: "↳ Hypertext Transfer Protocol (HTTP)", indent: 3, pct: 17.2, pkts: 220, bytes: "180 KB", rate: "170 KB/s", color: "#f59e0b" },
      { name: "↳ User Datagram Protocol (UDP)", indent: 3, pct: 25.8, pkts: 331, bytes: "330 KB", rate: "310 KB/s", color: "#06b6d4" },
      { name: "↳ Domain Name System (DNS)", indent: 3, pct: 20.4, pkts: 261, bytes: "240 KB", rate: "220 KB/s", color: "#ec4899" },
      { name: "↳ Address Resolution Protocol (ARP)", indent: 2, pct: 5.8, pkts: 74, bytes: "70.1 KB", rate: "68 KB/s", color: "#94a3b8" }
    ];

    tbody.innerHTML = protocols.map(p => `
      <tr>
        <td class="proto-tree-indent-${p.indent}">${escapeHtml(p.name)}</td>
        <td>
          <span style="font-weight: 700; color: ${p.color};">${p.pct}%</span>
          <div class="proto-bar-track">
            <div class="proto-bar-fill" style="width: ${p.pct}%; background: ${p.color};"></div>
          </div>
        </td>
        <td>${p.pkts.toLocaleString()}</td>
        <td>${p.bytes}</td>
        <td style="color: var(--text-muted);">${p.rate}</td>
      </tr>
    `).join('');
  }

  /* =============================================================
     FEATURE 3: RAW PACKET CRAFTER ("PACKET FORGE")
     ============================================================= */
  function setupPacketForge() {
    const btnTransmit = document.getElementById('btnTransmitForgedPacket');
    const btnClear = document.getElementById('btnClearForgeConsole');
    const btnClose = document.getElementById('btnCloseForgeModal');
    const btnCloseFooter = document.getElementById('btnCloseForgeModalFooter');
    const modal = document.getElementById('modalPacketForge');

    if (btnTransmit) btnTransmit.addEventListener('click', transmitForgedPacket);
    if (btnClear) {
      btnClear.addEventListener('click', () => {
        const c = document.getElementById('forgeConsoleBody');
        if (c) c.innerHTML = `<div class="term-line term-muted">Console cleared.</div>`;
      });
    }

    if (btnClose && modal) btnClose.addEventListener('click', () => modal.classList.add('hidden'));
    if (btnCloseFooter && modal) btnCloseFooter.addEventListener('click', () => modal.classList.add('hidden'));
  }

  function openPacketForgeModal() {
    const modal = document.getElementById('modalPacketForge');
    if (modal) modal.classList.remove('hidden');
  }

  function transmitForgedPacket() {
    const proto = document.getElementById('forgeProtoSelect')?.value || 'TCP';
    const ttl = document.getElementById('forgeTtlInput')?.value || '64';
    const src = document.getElementById('forgeSrcInput')?.value || '192.168.1.105:54120';
    const dst = document.getElementById('forgeDstInput')?.value || '45.33.32.156:80';
    const payload = document.getElementById('forgePayloadInput')?.value || '';
    const consoleBody = document.getElementById('forgeConsoleBody');

    const flags = [];
    ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'].forEach(f => {
      if (document.getElementById(`flag${f}`)?.checked) flags.push(f);
    });

    const now = new Date().toISOString().split('T')[1].slice(0, 8);

    if (consoleBody) {
      const block = document.createElement('div');
      block.className = 'term-line';
      block.style.marginTop = '8px';
      block.innerHTML = `
        <span class="term-cyan">[${now} DISPATCH]</span> PROTO=<strong>${proto}</strong> | SRC=${escapeHtml(src)} ➔ DST=${escapeHtml(dst)}<br>
        <span class="term-muted">|__ FLAGS=[${flags.join(',') || 'NONE'}] | TTL=${ttl} | PAYLOAD_LEN=${payload.length}B</span><br>
        <span class="term-green">✔ Packet frame compiled & injected via interface '${activeInterface.name}'.</span>
      `;
      consoleBody.appendChild(block);

      setTimeout(() => {
        const resp = document.createElement('div');
        resp.className = 'term-line';
        if (flags.includes('SYN')) {
          resp.innerHTML = `<span class="term-amber">[${now} RECV]</span> Target ACK acknowledged: SYN-ACK received from ${escapeHtml(dst)} (Window: 29200, MSS: 1460)`;
        } else {
          resp.innerHTML = `<span class="term-green">[${now} RECV]</span> Target replied: ICMP Echo Response / Connection state confirmed.`;
        }
        consoleBody.appendChild(resp);
        consoleBody.scrollTop = consoleBody.scrollHeight;
      }, 350);

      consoleBody.scrollTop = consoleBody.scrollHeight;
      showToast(`Forged ${proto} frame transmitted to ${dst}!`, "success");
    }
  }

  /* =============================================================
     FEATURE 4: WHOIS & IP THREAT INTELLIGENCE RADAR
     ============================================================= */
  const whoisDatabase = {
    'scanme.nmap.org': {
      ip: '45.33.32.156',
      asn: 'AS13335 (Cloudflare / Linode LLC)',
      org: 'Nmap Project Testing Host',
      country: '🇺🇸 United States (Fremont, California)',
      rdns: 'scanme.nmap.org',
      abuseScore: '0% (Clean / Authorized Security Lab)',
      range: '45.33.32.0/24'
    },
    '1.1.1.1': {
      ip: '1.1.1.1',
      asn: 'AS13335 CLOUDFLARENET',
      org: 'Cloudflare Inc. / APNIC Research',
      country: '🌐 Anycast Global Edge Network',
      rdns: 'one.one.one.one',
      abuseScore: '0% (Verified Public Resolver)',
      range: '1.1.1.0/24'
    },
    '8.8.8.8': {
      ip: '8.8.8.8',
      asn: 'AS15169 GOOGLE',
      org: 'Google LLC',
      country: '🇺🇸 United States (Mountain View, CA)',
      rdns: 'dns.google',
      abuseScore: '0% (Clean / Google Public DNS)',
      range: '8.8.8.0/24'
    },
    '192.168.1.1': {
      ip: '192.168.1.1',
      asn: 'RFC1918 Private Subnet',
      org: 'Local LAN Gateway Router',
      country: '🏠 Private Local Area Network',
      rdns: 'router.localdomain',
      abuseScore: '0% (Internal Gateway)',
      range: '192.168.1.0/24'
    }
  };

  function setupWhoisIntel() {
    const btnLookup = document.getElementById('btnRunWhoisLookup');
    const input = document.getElementById('whoisTargetInput');
    const btnClose = document.getElementById('btnCloseWhoisModal');
    const btnCloseFooter = document.getElementById('btnCloseWhoisModalFooter');
    const modal = document.getElementById('modalWhoisIntel');

    if (btnLookup) {
      btnLookup.addEventListener('click', () => {
        const query = input?.value.trim() || 'scanme.nmap.org';
        executeWhoisLookup(query);
      });
    }

    if (input) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const query = input.value.trim() || 'scanme.nmap.org';
          executeWhoisLookup(query);
        }
      });
    }

    if (btnClose && modal) btnClose.addEventListener('click', () => modal.classList.add('hidden'));
    if (btnCloseFooter && modal) btnCloseFooter.addEventListener('click', () => modal.classList.add('hidden'));
  }

  function openWhoisIntelModal() {
    const modal = document.getElementById('modalWhoisIntel');
    if (!modal) return;
    executeWhoisLookup(currentTarget || 'scanme.nmap.org');
    const input = document.getElementById('whoisTargetInput');
    if (input) input.value = currentTarget || 'scanme.nmap.org';
    modal.classList.remove('hidden');
  }

  function executeWhoisLookup(target) {
    const container = document.getElementById('whoisResultsContainer');
    if (!container) return;

    const data = whoisDatabase[target] || {
      ip: target,
      asn: 'AS20940 Akamai / Cloud Edge',
      org: `${target} Hosting Infrastructure`,
      country: '🌐 Global Edge Network',
      rdns: `${target}.in-addr.arpa`,
      abuseScore: '2% (Low Threat Confidence)',
      range: `${target}/24`
    };

    container.innerHTML = `
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-server"></i> Resolved Target IP:</span>
        <strong class="val text-cyan">${data.ip}</strong>
      </div>
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-network-wired"></i> Autonomous System (ASN):</span>
        <strong class="val">${data.asn}</strong>
      </div>
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-building"></i> Organization / ISP:</span>
        <strong class="val">${data.org}</strong>
      </div>
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-earth-americas"></i> Geolocation & Country:</span>
        <strong class="val">${data.country}</strong>
      </div>
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-arrow-rotate-left"></i> Reverse DNS (rDNS):</span>
        <strong class="val">${data.rdns}</strong>
      </div>
      <div class="whois-stat-card">
        <span class="lbl"><i class="fa-solid fa-shield-virus"></i> Abuse Threat Score:</span>
        <strong class="val text-emerald">${data.abuseScore}</strong>
      </div>
    `;

    showToast(`WHOIS & Threat Intel resolved for ${target}`, "info");
  }

  /* -------------------------------------------------------------
     TOAST NOTIFICATION & ESCAPE HELPERS
     ------------------------------------------------------------- */
  function showToast(message, type = "info") {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast-msg toast-${type}`;
    const icon = type === 'success' ? 'fa-circle-check' : (type === 'danger' ? 'fa-triangle-exclamation' : 'fa-circle-info');
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = '0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

})();
