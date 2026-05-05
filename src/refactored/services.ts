import { IFirewallService, ITicketingSystem } from '../interfaces';

// Реалізації DIP (Модулі нижнього рівня)
export class EnterpriseFirewall implements IFirewallService {
    blockIp(ip: string): boolean {
        console.log(`[Enterprise FW] Rule applied. Traffic from ${ip} dropped.`);
        return true;
    }
}

export class SecOpsTicketing implements ITicketingSystem {
    createIncidentTicket(description: string): void {
        console.log(`[SecOps Portal] New Alert: ${description}`);
    }
}