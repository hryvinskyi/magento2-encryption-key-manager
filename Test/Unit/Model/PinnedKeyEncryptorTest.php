<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Test\Unit\Model;

use Hryvinskyi\EncryptionKeyManager\Api\PinnedHashKeyInterface;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedKeyDeploymentConfig;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedKeyDeploymentConfigFactory;
use Hryvinskyi\EncryptionKeyManager\Model\PinnedKeyEncryptor;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\DeploymentConfig\Reader;
use Magento\Framework\Encryption\Encryptor;
use Magento\Framework\Encryption\EncryptorFactory;
use Magento\Framework\Encryption\KeyValidator;
use Magento\Framework\Math\Random;
use PHPUnit\Framework\TestCase;

/**
 * Compares the pinned hashes with the hashes the store's own encryptor computes
 */
class PinnedKeyEncryptorTest extends TestCase
{
    private const OLD_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
    private const ACTIVE_KEY = 'f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5';
    private const IMAGE_PARAMS = 'h:265_w:265_proportional_frame_constrainonly_rgb255,255,255_quality:80'
        . '_image_type:small_image';

    /**
     * With a pinned key the hash is the one the store computed while that key was its active key
     *
     * @return void
     */
    public function testHashesWithThePinnedKeyAsTheStoreDidWhileItWasActive(): void
    {
        $encryptor = $this->encryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY, self::OLD_KEY);
        $whileOldKeyWasActive = $this->storeEncryptor(self::OLD_KEY);

        self::assertSame(
            $whileOldKeyWasActive->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5),
            $encryptor->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5)
        );
        self::assertSame(
            $whileOldKeyWasActive->hash(self::IMAGE_PARAMS),
            $encryptor->hash(self::IMAGE_PARAMS)
        );
        $afterRotation = $this->storeEncryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY);
        self::assertNotSame(
            $afterRotation->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5),
            $encryptor->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5)
        );
    }

    /**
     * Without a pinned key the hash is the store's, with its active key
     *
     * @return void
     */
    public function testHashesAsTheStoreDoesWithoutAPin(): void
    {
        $ring = self::OLD_KEY . "\n" . self::ACTIVE_KEY;

        self::assertSame(
            $this->storeEncryptor($ring)->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5),
            $this->encryptor($ring, null)->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5)
        );
    }

    /**
     * A ring given through the environment moves the store's hashes, never the pinned ones
     *
     * @return void
     */
    public function testAnEnvironmentOverrideOfTheRingDoesNotMoveThePinnedHash(): void
    {
        $expected = $this->storeEncryptor(self::OLD_KEY)->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5);
        putenv('MAGENTO_DC_CRYPT__KEY=' . self::ACTIVE_KEY);
        putenv('MAGENTO_DC__OVERRIDE=' . json_encode(['crypt' => ['key' => self::ACTIVE_KEY]], JSON_THROW_ON_ERROR));
        try {
            $hash = $this->encryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY, self::OLD_KEY)
                ->hash(self::IMAGE_PARAMS, Encryptor::HASH_VERSION_MD5);
        } finally {
            putenv('MAGENTO_DC_CRYPT__KEY');
            putenv('MAGENTO_DC__OVERRIDE');
        }

        self::assertSame($expected, $hash);
    }

    /**
     * The pin is read once per instance
     *
     * @return void
     */
    public function testReadsThePinOnce(): void
    {
        $built = 0;
        $reads = 0;
        $encryptor = $this->encryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY, null, $built, $reads);

        $encryptor->hash('a', Encryptor::HASH_VERSION_MD5);
        $encryptor->hash('b', Encryptor::HASH_VERSION_MD5);

        self::assertSame(1, $reads);
    }

    /**
     * The encryptor for a pinned key is built once and reused
     *
     * @return void
     */
    public function testBuildsThePinnedEncryptorOnce(): void
    {
        $built = 0;
        $encryptor = $this->encryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY, self::OLD_KEY, $built);

        $first = $encryptor->hash('a', Encryptor::HASH_VERSION_MD5);
        $encryptor->hash('b', Encryptor::HASH_VERSION_MD5);

        self::assertSame(1, $built);
        self::assertSame($first, $encryptor->hash('a', Encryptor::HASH_VERSION_MD5));
    }

    /**
     * Encryption and decryption stay the store's: the active key encrypts, every ring key decrypts
     *
     * @return void
     */
    public function testEncryptsAndDecryptsAsTheStore(): void
    {
        $ring = self::OLD_KEY . "\n" . self::ACTIVE_KEY;
        $encryptor = $this->encryptor($ring, self::OLD_KEY);
        $store = $this->storeEncryptor($ring);

        $ciphertext = $encryptor->encrypt('secret');

        self::assertStringStartsWith('1:3:', $ciphertext);
        self::assertSame('secret', $store->decrypt($ciphertext));
        self::assertSame('other', $encryptor->decrypt($this->storeEncryptor(self::OLD_KEY)->encrypt('other')));
    }

    /**
     * Password hashes stay the store's
     *
     * @return void
     */
    public function testPasswordHashesStayTheStores(): void
    {
        $encryptor = $this->encryptor(self::OLD_KEY . "\n" . self::ACTIVE_KEY, self::OLD_KEY);

        $hash = $encryptor->getHash('password', true);

        self::assertTrue($this->storeEncryptor(self::ACTIVE_KEY)->isValidHash('password', $hash));
        self::assertTrue($encryptor->isValidHash('password', $hash));
        self::assertTrue($encryptor->validateHash('password', $hash));
    }

    /**
     * Build the encryptor under test over a store with that ring and pinned key
     *
     * @param string $ring the store's key ring
     * @param string|null $pinned the pinned key, or null for none
     * @param int $built counts the pinned encryptors built
     * @param int $reads counts the reads of the pin
     * @return PinnedKeyEncryptor the encryptor
     */
    private function encryptor(string $ring, ?string $pinned, int &$built = 0, int &$reads = 0): PinnedKeyEncryptor
    {
        $pinnedHashKey = $this->createMock(PinnedHashKeyInterface::class);
        $pinnedHashKey->method('get')->willReturnCallback(static function () use ($pinned, &$reads): ?string {
            $reads++;

            return $pinned;
        });
        $deploymentConfigs = $this->createMock(PinnedKeyDeploymentConfigFactory::class);
        $deploymentConfigs->method('create')->willReturnCallback(
            function (array $arguments) use ($ring): PinnedKeyDeploymentConfig {
                $pinnedKey = $arguments['pinnedKey'] ?? null;
                self::assertIsString($pinnedKey);

                return new PinnedKeyDeploymentConfig(
                    $this->reader(['crypt' => ['key' => $ring], 'db' => []]),
                    $pinnedKey
                );
            }
        );
        $encryptors = $this->createMock(EncryptorFactory::class);
        $encryptors->method('create')->willReturnCallback(
            static function (array $arguments) use (&$built): Encryptor {
                $built++;
                $deploymentConfig = $arguments['deploymentConfig'] ?? null;
                self::assertInstanceOf(DeploymentConfig::class, $deploymentConfig);

                return new Encryptor(new Random(), $deploymentConfig, new KeyValidator());
            }
        );

        return new PinnedKeyEncryptor($this->storeEncryptor($ring), $pinnedHashKey, $encryptors, $deploymentConfigs);
    }

    /**
     * Build the store's own encryptor over a ring
     *
     * @param string $ring the key ring
     * @return Encryptor the encryptor
     */
    private function storeEncryptor(string $ring): Encryptor
    {
        return new Encryptor(
            new Random(),
            new DeploymentConfig($this->reader(['crypt' => ['key' => $ring]])),
            new KeyValidator()
        );
    }

    /**
     * A deployment configuration reader that returns fixed data
     *
     * @param array<string, mixed> $data what the configuration files hold
     * @return Reader the reader
     */
    private function reader(array $data): Reader
    {
        $reader = $this->createMock(Reader::class);
        $reader->method('load')->willReturn($data);

        return $reader;
    }
}
