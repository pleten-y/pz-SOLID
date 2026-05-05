// Порушення ISP: Інтерфейс вимагає методів, які застосовні не до всіх загроз
export interface IThreatMitigation {
    blockIpAddress(): void;
    quarantineFile(): void;
    deleteEmail(): void;
}

// Порушення DIP: Жорстка прив'язка до конкретних сервісів
class CiscoFirewallApi {
    applyBlockRule(ip: string) { console.log(`[Cisco ASA] Blocked IP: ${ip}`); }
}

class JiraTicketing {
    createTicket(issue: string) { console.log(`[Jira] Ticket created: ${issue}`); }
}

// Порушення SRP: Клас займається і маршрутизацією логіки, і фаєрволом, і тікетами
export class BadSecurityManager implements IThreatMitigation {
    private firewall = new CiscoFirewallApi();
    private ticketing = new JiraTicketing();

    public handleIncident(threatType: string, target: string) {
        // Порушення OCP: Щоб додати SQL Injection, доведеться змінювати цей метод
        if (threatType === "DDoS") {
            console.log(`Mitigating DDoS on ${target}`);
            this.firewall.applyBlockRule(target);
        } else if (threatType === "Malware") {
            console.log(`Isolating host ${target} due to malware.`);
        } else if (threatType === "Phishing") {
            console.log(`Analyzing phishing email for ${target}`);
        } else {
            throw new Error("Unknown threat type");
        }

        this.ticketing.createTicket(`Incident handled: ${threatType} on ${target}`);
    }

    public blockIpAddress(): void { console.log("IP Blocked"); }
    public quarantineFile(): void { console.log("File quarantined"); }
    public deleteEmail(): void { console.log("Email deleted"); }
}

// Порушення LSP: Нащадок ламає логіку базового класу. Фішинг не можна заблокувати простим баном IP.
export class PhishingIncident extends BadSecurityManager {
    public blockIpAddress(): void {
        throw new Error("Cannot block IP for a spoofed phishing email!");
    }
}