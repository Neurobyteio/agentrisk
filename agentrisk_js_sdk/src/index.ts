import axios from 'axios';

export class AgentRisk {
    private baseUrl: string;

    constructor(baseUrl: string = "https://api.agentrisk.dev") {
        this.baseUrl = baseUrl.replace(/\/+$/, "");
    }

    async quickScan(tokenAddress: string): Promise<any> {
        const response = await axios.get(`${this.baseUrl}/v1/token/quick`, { params: { address: tokenAddress } });
        return response.data;
    }

    async deepScan(tokenAddress: string, txHash?: string): Promise<{ statusCode: number; data: any }> {
        const params: any = { address: tokenAddress };
        if (txHash) params.tx_hash = txHash;
        try {
            const response = await axios.get(`${this.baseUrl}/v1/token/deep`, { params });
            return { statusCode: response.status, data: response.data };
        } catch (error: any) {
            if (error.response) return { statusCode: error.response.status, data: error.response.data };
            throw error;
        }
    }
}