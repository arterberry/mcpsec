import { ConfigManager } from '../../../src/core/config';
import { TestHelpers } from '../../utils/test-helpers';

jest.mock('fs');

describe('ConfigManager', () => {
    let configManager: ConfigManager;
    let mockFs: any;

    beforeEach(() => {
        configManager = ConfigManager.getInstance();
        mockFs = require('fs');
        jest.clearAllMocks();
    });

    describe('getInstance', () => {
        it('should return singleton instance', () => {
            const instance1 = ConfigManager.getInstance();
            const instance2 = ConfigManager.getInstance();

            expect(instance1).toBe(instance2);
        });
    });

    describe('loadConfig', () => {
        it('should load default config when no user config exists', () => {
            mockFs.existsSync.mockReturnValue(false);

            const config = configManager.loadConfig('/test/project');

            expect(config).toHaveProperty('rules');
            expect(config).toHaveProperty('foxCorp');
            expect(config.rules['auth-required']).toEqual({
                enabled: true,
                severity: 'error'
            });
        });

        it('should merge user config with defaults', () => {
            const userConfig = {
                rules: {
                    'auth-required': { enabled: false }
                },
                foxCorp: {
                    streamingAssets: false
                }
            };

            mockFs.existsSync.mockReturnValue(true);
            mockFs.readFileSync.mockReturnValue(JSON.stringify(userConfig));

            const config = configManager.loadConfig('/test/project', '.mcpsec.json');

            expect(config.rules['auth-required'].enabled).toBe(false);
            expect(config.foxCorp.streamingAssets).toBe(false);
            expect(config.rules['role-validation']).toEqual({
                enabled: true,
                severity: 'error'
            });
        });

        it('should find standard config files', () => {
            mockFs.existsSync.mockImplementation((path: string) =>
                path.includes('.mcpsec.json')
            );
            mockFs.readFileSync.mockReturnValue('{"rules":{}}');

            const config = configManager.loadConfig('/test/project');

            expect(mockFs.existsSync).toHaveBeenCalledWith(
                expect.stringContaining('.mcpsec.json')
            );
        });
    });

    describe('initializeConfig', () => {
        it('should create default config file', async () => {
            await configManager.initializeConfig('/test/project', 'basic');

            expect(mockFs.writeFileSync).toHaveBeenCalledWith(
                expect.stringContaining('.mcpsec.json'),
                expect.any(String),
                'utf-8'
            );
        });
    });

    describe('validateConfig', () => {
        it('should validate correct config', async () => {
            const validConfig = TestHelpers.createMockConfig();
            mockFs.readFileSync.mockReturnValue(JSON.stringify(validConfig));

            const isValid = await configManager.validateConfig('.mcpsec.json');

            expect(isValid).toBe(true);
        });

        it('should reject invalid config', async () => {
            mockFs.readFileSync.mockReturnValue('invalid json');

            const isValid = await configManager.validateConfig('.mcpsec.json');

            expect(isValid).toBe(false);
        });

        it('should reject config without rules', async () => {
            mockFs.readFileSync.mockReturnValue('{"invalid": true}');

            const isValid = await configManager.validateConfig('.mcpsec.json');

            expect(isValid).toBe(false);
        });
    });
});