// ISP: Спеціалізовані інтерфейси для різних типів стримування загроз
export interface INetworkBlockable {
    blockNetworkSource(): string;
}

export interface IFileQuarantinable {
    isolatePayload(): string;
}

export interface IEmailRemovable {
    purgeFromMailbox(): string;
}

// DIP: Абстракції для інфраструктурних сервісів
export interface IFirewallService {
    blockIp(ip: string): boolean;
}

export interface ITicketingSystem {
    createIncidentTicket(description: string): void;
}

// OCP: Загальний контракт для аналізу загроз
export interface IThreatAnalyzer {
    calculateSeverity(): string;
}