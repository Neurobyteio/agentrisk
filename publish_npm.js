const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const sdkDir = '/var/www/agentrisk/agentrisk_js_sdk';

if (fs.existsSync(sdkDir)) {
    fs.rmSync(sdkDir, { recursive: true, force: true });
}

fs.mkdirSync(path.join(sdkDir, 'src'), { recursive: true });

const packageJson = {
    name: "agentrisk-sdk",
    version: "1.0.0",
    description: "Official JS/TS SDK for AgentRisk API (Base Network Token Risk Scoring)",
    main: "dist/index.js",
    types: "dist/index.d.ts",
    scripts: { build: "tsc" },
    keywords: ["base", "crypto", "honeypot", "security", "ai-agent", "x402", "web3"],
    author: "AgentRisk Team",
    license: "MIT",
    dependencies: { axios: "^1.6.0" },
    devDependencies: { typescript: "^5.0.0", "@types/node": "^20.0.0" }
};

fs.writeFileSync(path.join(sdkDir, 'package.json'), JSON.stringify(packageJson, null, 2));

const tsConfig = {
    compilerOptions: {
        target: "ES2020",
        module: "CommonJS",
        declaration: true,
        outDir: "./dist",
        strict: true,
        esModuleInterop: true
    },
    include: ["src/**/*"]
};

fs.writeFileSync(path.join(sdkDir, 'tsconfig.json'), JSON.stringify(tsConfig, null, 2));

const tsCode = `import axios from 'axios';

export class AgentRisk {
    private baseUrl: string;

    constructor(baseUrl: string = "https://api.agentrisk.dev") {
        this.baseUrl = baseUrl.replace(/\\/+$/, "");
    }

    async quickScan(tokenAddress: string): Promise<any> {
        const response = await axios.get(\`\${this.baseUrl}/v1/token/quick\`, { params: { address: tokenAddress } });
        return response.data;
    }

    async deepScan(tokenAddress: string, txHash?: string): Promise<{ statusCode: number; data: any }> {
        const params: any = { address: tokenAddress };
        if (txHash) params.tx_hash = txHash;
        try {
            const response = await axios.get(\`\${this.baseUrl}/v1/token/deep\`, { params });
            return { statusCode: response.status, data: response.data };
        } catch (error: any) {
            if (error.response) return { statusCode: error.response.status, data: error.response.data };
            throw error;
        }
    }
}`;

fs.writeFileSync(path.join(sdkDir, 'src/index.ts'), tsCode);
fs.writeFileSync(path.join(sdkDir, 'README.md'), `# AgentRisk JS/TS SDK\n\nOfficial Node.js/TypeScript client for **AgentRisk API** on Base Network.\n\n## Installation\n\`\`\`bash\nnpm install agentrisk-sdk\n\`\`\`\n`);

console.log("Compiling JS SDK...");
execSync('npm install && npm run build', { cwd: sdkDir, stdio: 'inherit' });
console.log("SUCCESS: JS SDK built successfully!");
