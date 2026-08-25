"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentRisk = void 0;
const axios_1 = __importDefault(require("axios"));
class AgentRisk {
    constructor(baseUrl = "https://api.agentrisk.dev") {
        this.baseUrl = baseUrl.replace(/\/+$/, "");
    }
    async quickScan(tokenAddress) {
        const response = await axios_1.default.get(`${this.baseUrl}/v1/token/quick`, { params: { address: tokenAddress } });
        return response.data;
    }
    async deepScan(tokenAddress, txHash) {
        const params = { address: tokenAddress };
        if (txHash)
            params.tx_hash = txHash;
        try {
            const response = await axios_1.default.get(`${this.baseUrl}/v1/token/deep`, { params });
            return { statusCode: response.status, data: response.data };
        }
        catch (error) {
            if (error.response)
                return { statusCode: error.response.status, data: error.response.data };
            throw error;
        }
    }
}
exports.AgentRisk = AgentRisk;
