import { connect } from "cloudflare:sockets";

// Configuration Block
let subscriptionPath = "subscription-path";
let camouflageWebpage;
let validateUUID;
let preferredLink = "https://raw.githubusercontent.com/ImLTHQ/edgetunnel/main/output.txt";
let preferredList = [];
let nat64Prefix = "2a02:898:146:64::";
let dohAddress = "1.1.1.1";
let proxyIP = "proxyip.cmliussss.net";
let customSNI = ""; // [NEW] Custom SNI feature

// Keyword splitting (anti-detection)
const v2raySplit = ["v2", "ray"];
const clashSplit = ["cla", "sh"];
const vlessSplit = ["vl", "ess"];

const v2ray = v2raySplit.join("");
const clash = clashSplit.join("");
const vless = vlessSplit.join("");

// Web Entry Point
export default {
  async fetch(request, env) {
    subscriptionPath = env.SUB_PATH ?? subscriptionPath;
    validateUUID = generateUUID();
    preferredLink = env.TXT_URL ?? preferredLink;
    nat64Prefix = env.NAT64 ?? nat64Prefix;
    dohAddress = env.DOH ?? dohAddress;
    proxyIP = env.PROXY_IP ?? proxyIP;
    camouflageWebpage = env.FAKE_WEB;
    customSNI = env.CUSTOM_SNI ?? ""; // [NEW] Load custom SNI from env var

    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");
    const isWSRequest = upgradeHeader == "websocket";

    const pathConfig = {
      v2ray: `/${encodeURIComponent(subscriptionPath)}/${v2ray}`,
      clash: `/${encodeURIComponent(subscriptionPath)}/${clash}`,
      subscriptionInfo: `/${encodeURIComponent(subscriptionPath)}/info`,
      universalSubscription: `/${encodeURIComponent(subscriptionPath)}`,
    };

    const isValidPath = url.pathname === pathConfig.v2ray ||
                      url.pathname === pathConfig.clash ||
                      url.pathname === pathConfig.subscriptionInfo ||
                      url.pathname === `/${encodeURIComponent(subscriptionPath)}`;

    if (!isWSRequest && !isValidPath) {
      if (camouflageWebpage) {
        try {
          const targetBase = camouflageWebpage.startsWith('http://') || camouflageWebpage.startsWith('https://')
            ? camouflageWebpage
            : `https://${camouflageWebpage}`;

          const targetUrl = new URL(targetBase);
          targetUrl.pathname = url.pathname;
          targetUrl.search = url.search;

          const requestObj = new Request(targetUrl.toString(), {
            method: request.method,
            headers: request.headers,
            body: request.body,
          });

          const responseObj = await fetch(requestObj);
          return responseObj;
        } catch {
          console.error(`[Camouflage webpage request failed] Target: ${camouflageWebpage}`);
          return new Response(null, { status: 404 });
        }
      } else {
        return new Response(null, { status: 404 });
      }
    }

    if (!isWSRequest) {
      if (isValidPath) {
        preferredList = await fetchPreferredList();
      }

      if (url.pathname === pathConfig.v2ray) {
        return generateV2rayConfig(request.headers.get("Host"));
      }
      else if (url.pathname === pathConfig.clash) {
        return generateClashConfig(request.headers.get("Host"));
      }
      else if (url.pathname === pathConfig.subscriptionInfo) {
        return generateAggregatedInfo(request.headers.get("Host"));
      }
      else if (url.pathname === pathConfig.universalSubscription) {
        const userAgent = request.headers.get("User-Agent").toLowerCase();
        const configGenerators = {
          [v2ray]: generateV2rayConfig,
          [clash]: generateClashConfig,
          tips: generateTipsPage,
        };
        const matchedTool = Object.keys(configGenerators).find((tool) => userAgent.includes(tool));
        preferredList = await fetchPreferredList();
        const generateConfig = configGenerators[matchedTool || "tips"];
        return generateConfig(request.headers.get("Host"));
      }
    }

    if (isWSRequest) {
      return await upgradeToWS(request);
    }
  },
};

// Main Script Architecture
async function upgradeToWS(request) {
  const wsPair = new WebSocketPair();
  const [client, ws] = Object.values(wsPair);
  ws.accept();
  ws.send(new Uint8Array([0, 0]));
  startTransmissionPipeline(ws, request);
  return new Response(null, { status: 101, webSocket: client });
}

async function startTransmissionPipeline(ws, request) {
  let tcpSocket,
    isFirstPacket = false,
    firstPacketPromise = Promise.resolve(),
    writer;
    
  ws.addEventListener("message", async (event) => {
    firstPacketPromise = firstPacketPromise.then(async () => {
      if (!isFirstPacket) {
        isFirstPacket = true;
        await parseVLESSHeader(event.data, request);
      } else {
        await writer.write(event.data);
      }
    });
  });

  async function parseVLESSHeader(vlessData, request) {
    if (validateVLESSKey(new Uint8Array(vlessData.slice(1, 17))) !== validateUUID) {
      return new Response(null, { status: 400 });
    }

    const optionLength = new Uint8Array(vlessData)[17];
    const portIndex = 18 + optionLength + 1;
    const portBuffer = vlessData.slice(portIndex, portIndex + 2);
    const targetPort = new DataView(portBuffer).getUint16(0);

    const addressIndex = portIndex + 2;
    const addressTypeBuffer = new Uint8Array(vlessData.slice(addressIndex, addressIndex + 1));
    const addressType = addressTypeBuffer[0];

    let addressLength = 0;
    let targetAddress = "";
    let addressInfoIndex = addressIndex + 1;

    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        targetAddress = new Uint8Array(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength)).join(".");
        break;
      case 2: // Domain
        addressLength = new Uint8Array(vlessData.slice(addressInfoIndex, addressInfoIndex + 1))[0];
        addressInfoIndex += 1;
        targetAddress = new TextDecoder().decode(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength));
        break;
      case 3: // IPv6
        addressLength = 16;
        const dataView = new DataView(vlessData.slice(addressInfoIndex, addressInfoIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(dataView.getUint16(i * 2).toString(16));
        }
        targetAddress = ipv6.join(":");
        break;
      default:
        return new Response(null, { status: 400 });
    }

    const initialData = vlessData.slice(addressInfoIndex + addressLength);

    try {
      // Step 1: Try direct connection
      tcpSocket = await connect({ hostname: targetAddress, port: targetPort, allowHalfOpen: true });
      await tcpSocket.opened;
    } catch {
      // Direct connection failed, check for NAT64 prefix
      if (nat64Prefix) {
        try {
          // Step 2: Try NAT64 connection
          const nat64Address = addressType === 1
            ? convertIPv4ToNAT64(targetAddress)
            : convertIPv4ToNAT64(await resolveDomainToIPv4(targetAddress));
          tcpSocket = await connect({ hostname: nat64Address, port: targetPort });
          await tcpSocket.opened;
        } catch {
          // NAT64 failed, try proxy
          if (proxyIP) {
            try {
              let [proxyIPAddr, proxyIPPort] = proxyIP.split(":");
              tcpSocket = await connect({
                hostname: proxyIPAddr,
                port: proxyIPPort || 443,
              });
              await tcpSocket.opened;
            } catch {
              console.error("All connection attempts failed");
            }
          } else {
            console.error("All connection attempts failed");
          }
        }
      } else {
        // No NAT64 prefix, try proxy connection
        if (proxyIP) {
          try {
            let [proxyIPAddr, proxyIPPort] = proxyIP.split(":");
            tcpSocket = await connect({
              hostname: proxyIPAddr,
              port: proxyIPPort || 443,
            });
            await tcpSocket.opened;
          } catch {
            console.error("All connection attempts failed");
          }
        } else {
          console.error("Direct connection only but failed");
        }
      }
    }

    establishTransmissionPipeline(initialData);
  }

  function validateVLESSKey(arr, offset = 0) {
    const uuid = (
      hexFormat[arr[offset + 0]] +
      hexFormat[arr[offset + 1]] +
      hexFormat[arr[offset + 2]] +
      hexFormat[arr[offset + 3]] +
      "-" +
      hexFormat[arr[offset + 4]] +
      hexFormat[arr[offset + 5]] +
      "-" +
      hexFormat[arr[offset + 6]] +
      hexFormat[arr[offset + 7]] +
      "-" +
      hexFormat[arr[offset + 8]] +
      hexFormat[arr[offset + 9]] +
      "-" +
      hexFormat[arr[offset + 10]] +
      hexFormat[arr[offset + 11]] +
      hexFormat[arr[offset + 12]] +
      hexFormat[arr[offset + 13]] +
      hexFormat[arr[offset + 14]] +
      hexFormat[arr[offset + 15]]
    ).toLowerCase();
    return uuid;
  }

  const hexFormat = [];
  for (let i = 0; i < 256; ++i) {
    hexFormat.push((i + 256).toString(16).slice(1));
  }

  async function establishTransmissionPipeline(initialData) {
    writer = tcpSocket.writable.getWriter();
    if (initialData) await writer.write(initialData);
    tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(vlessData) {
          ws.send(vlessData);
        },
      })
    );
  }
}

// Utility Functions
function convertIPv4ToNAT64(ipv4Address) {
  const cleanedPrefix = nat64Prefix.replace(/\/\d+$/, '');
  const hex = ipv4Address.split(".").map(segment => (+segment).toString(16).padStart(2, "0"));
  return `[${cleanedPrefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
}

async function resolveDomainToIPv4(domain) {
  const { Answer } = await (await fetch(`https://${dohAddress}/dns-query?name=${domain}&type=A`, {
    headers: { "Accept": "application/dns-json" }
  })).json();
  return Answer.find(({ type }) => type === 1).data;
}

function generateUUID() {
  const twentyChars = Array.from(new TextEncoder().encode(subscriptionPath))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 20)
    .padEnd(20, "0");

  const firstEight = twentyChars.slice(0, 8);
  const lastTwelve = twentyChars.slice(-12);

  return `${firstEight}-0000-4000-8000-${lastTwelve}`;
}

async function fetchPreferredList() {
  let rawList = [];
  if (preferredLink) {
    try {
      const response = await fetch(preferredLink);
      const text = await response.text();
      rawList = text
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line);

      if (rawList.length > 0) {
        return rawList;
      }
    }
    catch {
        return [];
    }
  }
  return [];
}

function processPreferredList(preferredList, hostName) {
  // [NEW] Use custom SNI if configured, otherwise use hostname
  const effectiveSNI = customSNI || hostName;
  
  preferredList.unshift(`${hostName}#native-node`);
  return preferredList.map((entry, index) => {
    const [addressPort, nodeName = `node-${index + 1}`] = entry.split("#");
    const parts = addressPort.split(":");
    const port = parts.length > 1 ? Number(parts.pop()) : 443;
    const address = parts.join(":");
    return { address, port, nodeName, sni: effectiveSNI };
  });
}

// Subscription Pages
async function generateTipsPage() {
  const tipsPage = `
<title>Subscription-${subscriptionPath}</title>
<style>
  body {
    font-size: 25px;
    text-align: center;
    margin: 0;
    padding: 0;
    height: 100vh;
    width: 100vw;
    display: flex;
    align-items: center;
    justify-content: center;
    box-sizing: border-box;
    overflow: hidden;
  }
</style>
<strong>Please import the link into ${clash} or ${v2ray}</strong>
`;

  return new Response(tipsPage, {
    status: 200,
    headers: { "Content-Type": "text/html;charset=utf-8" },
  });
}

function generateV2rayConfig(hostName) {
  const nodeList = processPreferredList(preferredList, hostName);
  const configContent = nodeList
    .map(({ address, port, nodeName, sni }) => {
      // [NEW] Use custom SNI in the config if set
      const effectiveSNI = sni || hostName;
      return `${vless}://${validateUUID}@${address}:${port}?encryption=none&security=tls&sni=${effectiveSNI}&fp=chrome&type=ws&host=${hostName}#${nodeName}`;
    })
    .join("\n");

  return new Response(configContent);
}

function generateClashConfig(hostName) {
  const nodeList = processPreferredList(preferredList, hostName);
  const generateNodes = (nodes) => {
    return nodes.map(({ address, port, nodeName, sni }) => {
      // [NEW] Use custom SNI in the config if set
      const effectiveSNI = sni || hostName;
      return {
        nodeConfig: `- name: ${nodeName}
  type: ${vless}
  server: ${address}
  port: ${port}
  uuid: ${validateUUID}
  udp: true
  tls: true
  sni: ${effectiveSNI}
  network: ws
  ws-opts:
    headers:
      Host: ${hostName}
      User-Agent: Chrome`,
        proxyConfig: `    - ${nodeName}`,
      };
    });
  };

  const nodeConfigs = generateNodes(nodeList)
    .map((node) => node.nodeConfig)
    .join("\n");
  const proxyConfigs = generateNodes(nodeList)
    .map((node) => node.proxyConfig)
    .join("\n");

  const configContent = `
proxies:
${nodeConfigs}

proxy-groups:
- name: overseas-rules
  type: select
  proxies:
    - latency-preferred
    - fallback
    - DIRECT
    - REJECT
${proxyConfigs}
- name: domestic-rules
  type: select
  proxies:
    - DIRECT
    - latency-preferred
    - fallback
    - REJECT
${proxyConfigs}
- name: ad-blocking
  type: select
  proxies:
    - REJECT
    - DIRECT
    - latency-preferred
    - fallback
${proxyConfigs}
- name: latency-preferred
  type: url-test
  url: https://www.google.com/generate_204
  interval: 30
  tolerance: 50
  proxies:
${proxyConfigs}
- name: fallback
  type: fallback
  url: https://www.google.com/generate_204
  interval: 30
  proxies:
${proxyConfigs}

rules:
  - GEOSITE,category-ads-all,ad-blocking
  - GEOSITE,cn,domestic-rules
  - GEOIP,CN,domestic-rules,no-resolve
  - MATCH,overseas-rules
`;

  return new Response(configContent);
}

function generateAggregatedInfo(hostName) {
  return new Response(`${hostName}#${validateUUID}`);
}
