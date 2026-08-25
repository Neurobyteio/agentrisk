export declare class AgentRisk {
    private baseUrl;
    constructor(baseUrl?: string);
    quickScan(tokenAddress: string): Promise<any>;
    deepScan(tokenAddress: string, txHash?: string): Promise<{
        statusCode: number;
        data: any;
    }>;
}
