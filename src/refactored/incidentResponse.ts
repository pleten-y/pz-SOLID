import { INetworkBlockable, IFileQuarantinable, IEmailRemovable, IFirewallService, ITicketingSystem } from '../interfaces';

// LSP: Абстрактний базовий клас для будь-якого кіберінциденту
export abstract class CyberThreat {
    constructor(
        public incidentId: string,
        public severityLevel: number
    ) {}

    // Кожна загроза має свій специфічний план реагування (Playbook)
    abstract executePlaybook(): string;
}

// OCP & ISP: Загрози імплементують лише ті інтерфейси, які мають технічний сенс
export class DdosAttack extends CyberThreat implements INetworkBlockable {
    constructor(id: string, severity: number, public attackerIp: string) {
        super(id, severity);
    }

    executePlaybook(): string {
        return this.blockNetworkSource();
    }

    blockNetworkSource(): string {
        return `Initiated network block for IP: ${this.attackerIp}`;
    }
}

export class RansomwarePayload extends CyberThreat implements IFileQuarantinable {
    constructor(id: string, severity: number, public filename: string) {
        super(id, severity);
    }

    executePlaybook(): string {
        return this.isolatePayload();
    }

    isolatePayload(): string {
        return `Process killed. File ${this.filename} moved to secure quarantine sandbox.`;
    }
}

export class SpearPhishing extends CyberThreat implements IEmailRemovable {
    constructor(id: string, severity: number, public messageId: string) {
        super(id, severity);
    }

    executePlaybook(): string {
        return this.purgeFromMailbox();
    }

    purgeFromMailbox(): string {
        return `Malicious email [MsgID: ${this.messageId}] deleted from all corporate inboxes.`;
    }
}

// SRP: SOAR-оркестратор відповідає ВИКЛЮЧНО за координацію процесу, а не за логіку блокування чи мережу
export class SoarOrchestrator {
    constructor(
        private firewall: IFirewallService,
        private ticketing: ITicketingSystem
    ) {}

    public mitigateThreat(threat: CyberThreat): void {
        if (threat.severityLevel > 10) {
            throw new Error("Critical severity threshold exceeded. Manual intervention required.");
        }

        // Поліморфний виклик (OCP/LSP)
        const mitigationResult = threat.executePlaybook();

        // Якщо загроза підтримує блокування мережі (ISP перевірка типу)
        if ('blockNetworkSource' in threat && threat instanceof DdosAttack) {
            this.firewall.blockIp(threat.attackerIp);
        }

        this.ticketing.createIncidentTicket(`Incident ${threat.incidentId} mitigated: ${mitigationResult}`);
    }
}