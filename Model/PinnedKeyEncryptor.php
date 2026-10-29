<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Model;

use Hryvinskyi\EncryptionKeyManager\Api\PinnedHashKeyInterface;
use Magento\Framework\Encryption\Encryptor;
use Magento\Framework\Encryption\EncryptorFactory;
use Magento\Framework\Encryption\EncryptorInterface;

/**
 * The store's encryptor, except that keyed hashes are computed with the pinned key when one is pinned
 *
 * Given to a class whose keyed hashes name something lasting, such as the cache directory of a resized product
 * image, it keeps those names when a key is appended to the ring and after the old key leaves it. The pinned hash is
 * computed by an encryptor of the store's own release whose ring is the pinned key alone, so it is exactly the hash
 * the store computed while that key was active. Without a pinned key it hashes as the store does now. Encryption,
 * decryption and password hashing are always the store's.
 *
 * The pin is read once per instance: it is written before a rotation and does not change while a process runs, and
 * reading a path the configuration does not hold makes the store reload its whole deployment configuration.
 *
 * The store's encryptor is taken as the class rather than its interface because only the class declares the hash
 * version argument that callers pass.
 */
class PinnedKeyEncryptor implements EncryptorInterface
{
    /**
     * @var array<string, Encryptor> pinned key entry => an encryptor whose ring is that key alone
     */
    private array $pinnedEncryptors = [];

    /**
     * @var bool whether the pin has been read
     */
    private bool $pinnedKeyRead = false;

    /**
     * @var string|null the pinned key, or null when none is pinned
     */
    private ?string $pinnedKey = null;

    /**
     * @param Encryptor $encryptor the store's encryptor
     * @param PinnedHashKeyInterface $pinnedHashKey the pinned key, when there is one
     * @param EncryptorFactory $encryptorFactory creates the encryptor that hashes with the pinned key
     * @param PinnedKeyDeploymentConfigFactory $deploymentConfigFactory creates the configuration that gives it its
     *                                                                 one key
     */
    public function __construct(
        private readonly Encryptor $encryptor,
        private readonly PinnedHashKeyInterface $pinnedHashKey,
        private readonly EncryptorFactory $encryptorFactory,
        private readonly PinnedKeyDeploymentConfigFactory $deploymentConfigFactory
    ) {
    }

    /**
     * Compute a keyed hash with the pinned key, or with the active key when none is pinned
     *
     * @param string $data the data to hash
     * @param int $version the hash version, one the store's encryptor supports
     * @return string the hash
     * @throws \RuntimeException when there is no key to hash with
     * @throws \InvalidArgumentException when the hash version is unknown
     */
    public function hash($data, $version = Encryptor::HASH_VERSION_SHA256)
    {
        if (!$this->pinnedKeyRead) {
            $this->pinnedKey = $this->pinnedHashKey->get();
            $this->pinnedKeyRead = true;
        }
        $key = $this->pinnedKey;
        $encryptor = $key === null ? $this->encryptor : $this->pinnedEncryptor($key);

        return $encryptor->hash($data, $version);
    }

    /**
     * @inheritDoc
     */
    public function getHash($password, $salt = false)
    {
        return $this->encryptor->getHash($password, $salt);
    }

    /**
     * @inheritDoc
     */
    public function validateHash($password, $hash)
    {
        return $this->encryptor->validateHash($password, $hash);
    }

    /**
     * @inheritDoc
     */
    public function isValidHash($password, $hash)
    {
        return $this->encryptor->isValidHash($password, $hash);
    }

    /**
     * @inheritDoc
     */
    public function validateHashVersion($hash, $validateCount = false)
    {
        return $this->encryptor->validateHashVersion($hash, $validateCount);
    }

    /**
     * @inheritDoc
     */
    public function encrypt($data)
    {
        return $this->encryptor->encrypt($data);
    }

    /**
     * @inheritDoc
     */
    public function decrypt($data)
    {
        return $this->encryptor->decrypt($data);
    }

    /**
     * @inheritDoc
     */
    public function validateKey($key)
    {
        return $this->encryptor->validateKey($key);
    }

    /**
     * Get the encryptor whose ring is the pinned key alone, built once per key
     *
     * @param string $key the pinned key entry
     * @return Encryptor the encryptor
     */
    private function pinnedEncryptor(string $key): Encryptor
    {
        return $this->pinnedEncryptors[$key] ??= $this->encryptorFactory->create([
            'deploymentConfig' => $this->deploymentConfigFactory->create(['pinnedKey' => $key]),
        ]);
    }
}
