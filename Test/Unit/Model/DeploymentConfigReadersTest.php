<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Model;

use Hryvinskyi\EncryptionKeyManager\Model\DecryptLogSettings;
use Hryvinskyi\EncryptionKeyManager\Model\DeploymentKeys;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedHashKey;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\DeploymentConfig\Reader;
use PHPUnit\Framework\TestCase;

/**
 * Reads the key ring, the kept keys, the pinned key and the log switch from the deployment configuration
 */
class DeploymentConfigReadersTest extends TestCase
{
    /**
     * The ring and the kept keys split on any whitespace, keeping each entry exactly
     *
     * @return void
     */
    public function testSplitsTheKeyLists(): void
    {
        $keys = new DeploymentKeys($this->config([
            'crypt' => ['key' => " k0\r\nk1 \n\tbase64ab+/= ", 'invalidated_key' => "old0\nold1"],
        ]));

        self::assertSame(['k0', 'k1', 'base64ab+/='], $keys->ring());
        self::assertSame(['old0', 'old1'], $keys->invalidated());
        self::assertSame([], (new DeploymentKeys($this->config(['crypt' => ['key' => '  ']])))->ring());
        self::assertSame([], (new DeploymentKeys($this->config([])))->invalidated());
    }

    /**
     * A blank or missing pin is no pin; a pin is read without its surrounding whitespace
     *
     * @return void
     */
    public function testReadsThePin(): void
    {
        self::assertSame('k0', (new PinnedHashKey($this->config(['crypt' => ['pinned_hash_key' => " k0\n"]])))->get());
        self::assertNull((new PinnedHashKey($this->config(['crypt' => ['pinned_hash_key' => ' ']])))->get());
        self::assertNull((new PinnedHashKey($this->config(['crypt' => []])))->get());
    }

    /**
     * The log switch is on only for a true value in the default scope of the system section
     *
     * @return void
     */
    public function testReadsTheLogSwitch(): void
    {
        $switch = static fn (mixed $value): array => [
            'system' => ['default' => ['dev' => ['debug' => ['log_old_key_decrypts' => $value]]]],
        ];

        self::assertTrue((new DecryptLogSettings($this->config($switch('1'))))->isEnabled());
        self::assertTrue((new DecryptLogSettings($this->config($switch(1))))->isEnabled());
        self::assertTrue((new DecryptLogSettings($this->config($switch(true))))->isEnabled());
        self::assertFalse((new DecryptLogSettings($this->config($switch('0'))))->isEnabled());
        self::assertFalse((new DecryptLogSettings($this->config($switch('false'))))->isEnabled());
        self::assertFalse((new DecryptLogSettings($this->config([])))->isEnabled());
    }

    /**
     * A deployment configuration over fixed data
     *
     * @param array<string, mixed> $data what the configuration files hold
     * @return DeploymentConfig the configuration
     */
    private function config(array $data): DeploymentConfig
    {
        $reader = $this->createMock(Reader::class);
        $reader->method('load')->willReturn($data);

        return new DeploymentConfig($reader);
    }
}
