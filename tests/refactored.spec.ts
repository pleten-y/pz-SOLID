import { SoarOrchestrator, DdosAttack, RansomwarePayload, SpearPhishing } from '../src/refactored/incidentResponse';
import { IFirewallService, ITicketingSystem } from '../src/interfaces';

describe('SoarOrchestrator (SOLID)', () => {
    let mockFirewall: IFirewallService;
    let mockTicketing: ITicketingSystem;
    let orchestrator: SoarOrchestrator;

    beforeEach(() => {
        // DIP: Ін'єкція залежностей через моки
        mockFirewall = { blockIp: jest.fn().mockReturnValue(true) };
        mockTicketing = { createIncidentTicket: jest.fn() };
        orchestrator = new SoarOrchestrator(mockFirewall, mockTicketing);
    });

    it('should correctly mitigate a DDoS attack and invoke firewall', () => {
        const ddos = new DdosAttack('INC-001', 8, '198.51.100.22');

        orchestrator.mitigateThreat(ddos);

        expect(mockFirewall.blockIp).toHaveBeenCalledWith('198.51.100.22');
        expect(mockTicketing.createIncidentTicket).toHaveBeenCalledWith(
            expect.stringContaining('Initiated network block for IP: 198.51.100.22')
        );
    });

    it('should correctly isolate Ransomware without calling the firewall (ISP & OCP)', () => {
        const malware = new RansomwarePayload('INC-002', 9, 'invoice_fake.exe');

        orchestrator.mitigateThreat(malware);

        // Фаєрвол не викликається для локальних файлів
        expect(mockFirewall.blockIp).not.toHaveBeenCalled();
        expect(mockTicketing.createIncidentTicket).toHaveBeenCalledWith(
            expect.stringContaining('File invoice_fake.exe moved to secure quarantine')
        );
    });

    it('should handle Spear Phishing correctly (LSP compliance)', () => {
        const phishing = new SpearPhishing('INC-003', 5, 'MSG-998877');

        // Раніше це могло викликати винятки в анти-патерні. Тепер працює безпечно.
        expect(() => orchestrator.mitigateThreat(phishing)).not.toThrow();

        expect(mockTicketing.createIncidentTicket).toHaveBeenCalledWith(
            expect.stringContaining('deleted from all corporate inboxes')
        );
    });

    it('should demand manual intervention for hyper-critical threats', () => {
        const aptThreat = new RansomwarePayload('INC-999', 15, 'system32_injector.dll');

        expect(() => orchestrator.mitigateThreat(aptThreat)).toThrow('Manual intervention required.');
    });
});