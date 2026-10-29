<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Model;

use Hryvinskyi\EncryptionKeyManager\Model\LatestKeyDeploymentConfig;
use Magento\Framework\App\DeploymentConfig\Reader;
use PHPUnit\Framework\TestCase;

/**
 * The key ring narrows to its active key; everything else reads as stored
 */
class LatestKeyDeploymentConfigTest extends TestCase
{
    private const OLD_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
    private const ACTIVE_KEY = 'f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5';

    /**
     * A ring of several keys reads as the last one
     *
     * @return void
     */
    public function testTheRingReadsAsItsActiveKey(): void
    {
        $config = $this->config(['crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY . "\n"]]);

        self::assertSame(self::ACTIVE_KEY, $config->get('crypt/key'));
    }

    /**
     * A ring of one key, other paths and a missing ring read as stored
     *
     * @return void
     */
    public function testEverythingElseReadsAsStored(): void
    {
        $config = $this->config([
            'crypt' => ['key' => self::ACTIVE_KEY, 'invalidated_key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY],
            'db' => ['table_prefix' => 'm_'],
        ]);

        self::assertSame(self::ACTIVE_KEY, $config->get('crypt/key'));
        self::assertSame(self::OLD_KEY . "\n" . self::ACTIVE_KEY, $config->get('crypt/invalidated_key'));
        self::assertSame('m_', $config->get('db/table_prefix'));
        self::assertSame('fallback', $this->config(['db' => []])->get('crypt/key', 'fallback'));
    }

    /**
     * Build the configuration over fixed data
     *
     * @param array<string, mixed> $data what the configuration files hold
     * @return LatestKeyDeploymentConfig the configuration
     */
    private function config(array $data): LatestKeyDeploymentConfig
    {
        $reader = $this->createMock(Reader::class);
        $reader->method('load')->willReturn($data);

        return new LatestKeyDeploymentConfig($reader);
    }
}
