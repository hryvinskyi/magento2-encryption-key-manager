<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Model;

use Hryvinskyi\EncryptionKeyManager\Model\DeploymentKeys;
use Hryvinskyi\EncryptionKeyManager\Model\HashKeyPinner;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedHashKey;
use Hryvinskyi\EncryptionKeyManager\Test\Unit\Fake\DeploymentConfigFiles;
use Magento\Framework\Exception\LocalizedException;
use PHPUnit\Framework\TestCase;

/**
 * Pins keys into a real app/etc/env.php through the store's own writer
 */
class HashKeyPinnerTest extends TestCase
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
     * Without a slot the active key is pinned; nothing else in the file changes
     *
     * @return void
     */
    public function testPinsTheActiveKeyByDefault(): void
    {
        $pinner = $this->pinner([
            'crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY],
            'db' => ['connection' => ['default' => ['host' => 'db']]],
        ]);

        $fingerprint = $pinner->pinRingKey(null, false);

        self::assertSame(substr(hash('sha256', self::ACTIVE_KEY), 0, 16), $fingerprint);
        self::assertSame([
            'crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY, 'pinned_hash_key' => self::ACTIVE_KEY],
            'db' => ['connection' => ['default' => ['host' => 'db']]],
        ], $this->files()->env());
    }

    /**
     * A slot pins the key in it
     *
     * @return void
     */
    public function testPinsTheKeyInAGivenSlot(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY]]);

        $pinner->pinRingKey(0, false);

        self::assertSame(self::OLD_KEY, $this->pinnedInFile());
    }

    /**
     * A slot that holds a retired key's placeholder is refused and nothing is written
     *
     * @return void
     */
    public function testRefusesAPlaceholderSlot(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::PLACEHOLDER . "\n" . self::ACTIVE_KEY]]);

        $this->assertRefusedWithoutWrite(static fn () => $pinner->pinRingKey(0, false), 'placeholder');
    }

    /**
     * A kept entry that is a retired key's placeholder is refused too
     *
     * @return void
     */
    public function testRefusesAPlaceholderAmongTheKeptKeys(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY, 'invalidated_key' => self::PLACEHOLDER]]);

        $this->assertRefusedWithoutWrite(static fn () => $pinner->pinInvalidatedKey(0, false), 'placeholder');
    }

    /**
     * A slot past the ring's end is refused
     *
     * @return void
     */
    public function testRefusesASlotTheRingDoesNotHave(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY]]);

        $this->assertRefusedWithoutWrite(static fn () => $pinner->pinRingKey(1, false), 'no slot 1');
    }

    /**
     * A configuration without a key ring is refused
     *
     * @return void
     */
    public function testRefusesWhenThereIsNoRing(): void
    {
        $pinner = $this->pinner(['db' => []]);

        $this->assertRefusedWithoutWrite(static fn () => $pinner->pinRingKey(null, false), 'no key ring');
    }

    /**
     * A kept key is pinned by its position among the kept keys
     *
     * @return void
     */
    public function testPinsAKeptKey(): void
    {
        $pinner = $this->pinner([
            'crypt' => [
                'key' => self::PLACEHOLDER . "\n" . self::ACTIVE_KEY,
                'invalidated_key' => self::OLD_KEY,
            ],
        ]);

        $fingerprint = $pinner->pinInvalidatedKey(0, false);

        self::assertSame(self::OLD_KEY, $this->pinnedInFile());
        self::assertSame(substr(hash('sha256', self::OLD_KEY), 0, 16), $fingerprint);
    }

    /**
     * A position past the kept keys, or kept keys that do not exist, are refused
     *
     * @return void
     */
    public function testRefusesAMissingKeptKey(): void
    {
        $withKept = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY, 'invalidated_key' => self::OLD_KEY]]);
        $this->assertRefusedWithoutWrite(
            static fn () => $withKept->pinInvalidatedKey(1, false),
            'no kept key at position 1'
        );
        $this->tearDown();

        $withoutKept = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY]]);
        $this->assertRefusedWithoutWrite(static fn () => $withoutKept->pinInvalidatedKey(0, false), 'keeps no keys');
    }

    /**
     * A different key that is already pinned stays unless the replacement is asked for
     *
     * @return void
     */
    public function testKeepsAnExistingPinUnlessReplacing(): void
    {
        $pinner = $this->pinner([
            'crypt' => ['key' => self::OLD_KEY . "\n" . self::ACTIVE_KEY, 'pinned_hash_key' => self::OLD_KEY],
        ]);

        try {
            $pinner->pinRingKey(null, false);
            self::fail('An existing pin was replaced without being asked to.');
        } catch (LocalizedException $exception) {
            self::assertStringContainsString(substr(hash('sha256', self::OLD_KEY), 0, 16), $exception->getMessage());
            self::assertStringNotContainsString(self::OLD_KEY, $exception->getMessage());
        }
        self::assertSame(self::OLD_KEY, $this->pinnedInFile());

        $pinner->pinRingKey(null, true);

        self::assertSame(self::ACTIVE_KEY, $this->pinnedInFile());
    }

    /**
     * Pinning the key that is already pinned succeeds without replacing anything
     *
     * @return void
     */
    public function testPinningTheSameKeyAgainIsAccepted(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY, 'pinned_hash_key' => self::ACTIVE_KEY]]);

        self::assertSame(substr(hash('sha256', self::ACTIVE_KEY), 0, 16), $pinner->pinRingKey(null, false));
        self::assertSame(self::ACTIVE_KEY, $this->pinnedInFile());
    }

    /**
     * An encoded key is fingerprinted by the bytes it encodes and pinned exactly as written
     *
     * @return void
     */
    public function testFingerprintsAnEncodedKeyByItsBytes(): void
    {
        $bytes = random_bytes(32);
        $entry = 'base64' . base64_encode($bytes);
        $pinner = $this->pinner(['crypt' => ['key' => $entry]]);

        self::assertSame(substr(hash('sha256', $bytes), 0, 16), $pinner->pinRingKey(null, false));
        self::assertSame($entry, $this->pinnedInFile());
    }

    /**
     * A deployment configuration that cannot be written is refused
     *
     * @return void
     */
    public function testRefusesAnUnwritableConfiguration(): void
    {
        $pinner = $this->pinner(['crypt' => ['key' => self::ACTIVE_KEY]]);
        chmod($this->files()->envPath(), 0400);

        $this->assertRefusedWithoutWrite(static fn () => $pinner->pinRingKey(null, false), 'must both be writable');
    }

    /**
     * Build a pinner over a fresh store root
     *
     * @param array<string, mixed> $env what app/etc/env.php returns
     * @return HashKeyPinner the pinner
     */
    private function pinner(array $env): HashKeyPinner
    {
        $this->files = new DeploymentConfigFiles($env);
        $deploymentConfig = $this->files->deploymentConfig();

        return new HashKeyPinner(
            new DeploymentKeys($deploymentConfig),
            new PinnedHashKey($deploymentConfig),
            $this->files->writer()
        );
    }

    /**
     * Assert that the call is refused with a message containing the text and that no key was pinned
     *
     * @param callable(): mixed $call the call
     * @param string $message text the refusal contains
     * @return void
     */
    private function assertRefusedWithoutWrite(callable $call, string $message): void
    {
        try {
            $call();
            self::fail('The pin was not refused.');
        } catch (LocalizedException $exception) {
            self::assertStringContainsString($message, $exception->getMessage());
        }
        self::assertNull($this->pinnedInFile());
    }

    /**
     * The pinned key as app/etc/env.php holds it now
     *
     * @return string|null the key, or null when none is pinned
     */
    private function pinnedInFile(): ?string
    {
        $crypt = $this->files()->env()['crypt'] ?? [];
        $pinned = is_array($crypt) ? ($crypt['pinned_hash_key'] ?? null) : null;

        return is_string($pinned) ? $pinned : null;
    }

    /**
     * The current store root
     *
     * @return DeploymentConfigFiles the files
     */
    private function files(): DeploymentConfigFiles
    {
        self::assertNotNull($this->files);

        return $this->files;
    }
}
