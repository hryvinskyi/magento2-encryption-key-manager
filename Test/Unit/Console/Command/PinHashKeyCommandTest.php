<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Console\Command;

use Hryvinskyi\EncryptionKeyManager\Console\Command\PinHashKeyCommand;
use Hryvinskyi\EncryptionKeyManager\Model\DeploymentKeys;
use Hryvinskyi\EncryptionKeyManager\Model\HashKeyPinner;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedHashKey;
use Hryvinskyi\EncryptionKeyManager\Test\Unit\Fake\DeploymentConfigFiles;
use Magento\Framework\Console\Cli;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Runs the command against a real app/etc/env.php
 */
class PinHashKeyCommandTest extends TestCase
{
    private const OLD_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
    private const ACTIVE_KEY = 'f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5';
    private const PLACEHOLDER = 'invalidAbCdEfGhIjKlMnOpQrStUvWxY';

    /**
     * @var DeploymentConfigFiles|null the current store root
     */
    private ?DeploymentConfigFiles $files = null;

    /**
     * @inheritDoc
     */
    protected function tearDown(): void
    {
        $this->files?->remove();
        $this->files = null;
    }

    /**
     * Without options the active key is pinned and only its fingerprint is printed
     *
     * @return void
     */
    public function testPinsTheActiveKey(): void
    {
        $tester = $this->tester(['crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY]]);

        self::assertSame(Cli::RETURN_SUCCESS, $tester->execute([]));
        self::assertStringContainsString(substr(hash('sha256', self::ACTIVE_KEY), 0, 16), $tester->getDisplay());
        self::assertStringNotContainsString(self::ACTIVE_KEY, $tester->getDisplay());
        self::assertSame(self::ACTIVE_KEY, $this->pinned());
    }

    /**
     * --slot and --invalidated choose the key
     *
     * @return void
     */
    public function testPinsTheChosenKey(): void
    {
        $env = ['crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY, 'invalidated_key' => self::PLACEHOLDER]];

        self::assertSame(Cli::RETURN_SUCCESS, $this->tester($env)->execute(['--slot' => '0']));
        self::assertSame(self::OLD_KEY, $this->pinned());
        $this->tearDown();

        $env = ['crypt' => ['key' => self::PLACEHOLDER . "\n" . self::ACTIVE_KEY, 'invalidated_key' => self::OLD_KEY]];
        self::assertSame(Cli::RETURN_SUCCESS, $this->tester($env)->execute(['--invalidated' => '0']));
        self::assertSame(self::OLD_KEY, $this->pinned());
    }

    /**
     * An existing pin is replaced only with --replace
     *
     * @return void
     */
    public function testReplacesAPinOnlyWhenAsked(): void
    {
        $tester = $this->tester([
            'crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY, 'pinned_hash_key' => self::OLD_KEY],
        ]);

        self::assertSame(Cli::RETURN_FAILURE, $tester->execute([]));
        self::assertSame(self::OLD_KEY, $this->pinned());
        self::assertSame(Cli::RETURN_SUCCESS, $tester->execute(['--replace' => true]));
        self::assertSame(self::ACTIVE_KEY, $this->pinned());
    }

    /**
     * Malformed or conflicting options are refused before anything is written
     *
     * @return void
     */
    public function testRefusesBadOptions(): void
    {
        $tester = $this->tester([
            'crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY, 'invalidated_key' => self::OLD_KEY],
        ]);
        $refused = [
            ['--slot' => '-1'],
            ['--slot' => 'one'],
            ['--invalidated' => '1.5'],
            ['--slot' => '0', '--invalidated' => '0'],
        ];

        foreach ($refused as $options) {
            $message = json_encode($options, JSON_THROW_ON_ERROR);
            self::assertSame(Cli::RETURN_FAILURE, $tester->execute($options), $message);
            self::assertStringContainsString('--', $tester->getDisplay());
        }
        self::assertNull($this->pinned());
    }

    /**
     * Build a tester of the command over a fresh store root
     *
     * @param array<string, mixed> $env what app/etc/env.php returns
     * @return CommandTester the tester
     */
    private function tester(array $env): CommandTester
    {
        $this->files = new DeploymentConfigFiles($env);
        $deploymentConfig = $this->files->deploymentConfig();

        return new CommandTester(new PinHashKeyCommand(new HashKeyPinner(
            new DeploymentKeys($deploymentConfig),
            new PinnedHashKey($deploymentConfig),
            $this->files->writer()
        )));
    }

    /**
     * The pinned key as app/etc/env.php holds it now
     *
     * @return string|null the key, or null when none is pinned
     */
    private function pinned(): ?string
    {
        self::assertNotNull($this->files);
        $crypt = $this->files->env()['crypt'] ?? [];
        $pinned = is_array($crypt) ? ($crypt['pinned_hash_key'] ?? null) : null;

        return is_string($pinned) ? $pinned : null;
    }
}
