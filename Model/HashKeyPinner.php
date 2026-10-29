<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Model;

use Hryvinskyi\EncryptionKeyManager\Api\DeploymentKeysInterface;
use Hryvinskyi\EncryptionKeyManager\Api\HashKeyPinnerInterface;
use Hryvinskyi\EncryptionKeyManager\Api\PinnedHashKeyInterface;
use Magento\Framework\App\DeploymentConfig\Writer;
use Magento\Framework\Config\File\ConfigFilePool;
use Magento\Framework\Exception\LocalizedException;

/**
 * Copies a key of the ring, or a kept key, to the pinned key path of the deployment configuration
 *
 * An entry that starts with `invalid` is the placeholder of a retired key, never a key the store hashed with, so
 * it is refused. A pin that is already there is kept unless replacing it is asked for. The pin is read back after the
 * write, so a write that did not land is reported rather than taken for done.
 */
class HashKeyPinner implements HashKeyPinnerInterface
{
    private const PLACEHOLDER_PREFIX = 'invalid';
    private const ENCODED_KEY_PREFIX = 'base64';

    /**
     * @param DeploymentKeysInterface $deploymentKeys the key ring and the kept keys
     * @param PinnedHashKeyInterface $pinnedHashKey the key pinned now
     * @param Writer $writer writes the deployment configuration
     */
    public function __construct(
        private readonly DeploymentKeysInterface $deploymentKeys,
        private readonly PinnedHashKeyInterface $pinnedHashKey,
        private readonly Writer $writer
    ) {
    }

    /**
     * @inheritDoc
     */
    public function pinRingKey(?int $slot, bool $replace): string
    {
        $ring = $this->deploymentKeys->ring();
        if ($ring === []) {
            throw new LocalizedException(__('The deployment configuration holds no key ring.'));
        }
        $slot ??= array_key_last($ring);
        $key = $ring[$slot] ?? null;
        if ($key === null) {
            throw new LocalizedException(
                __('The key ring has no slot %1; its slots are 0 to %2.', $slot, array_key_last($ring))
            );
        }

        return $this->pin($key, $replace);
    }

    /**
     * @inheritDoc
     */
    public function pinInvalidatedKey(int $position, bool $replace): string
    {
        $kept = $this->deploymentKeys->invalidated();
        $key = $kept[$position] ?? null;
        if ($key === null) {
            throw new LocalizedException(
                $kept === []
                    ? __('The deployment configuration keeps no keys taken out of the ring.')
                    : __(
                        'There is no kept key at position %1; the positions are 0 to %2.',
                        $position,
                        array_key_last($kept)
                    )
            );
        }

        return $this->pin($key, $replace);
    }

    /**
     * Write the key to the pinned key path and read it back
     *
     * @param string $key the key entry, exactly as the ring or the kept keys hold it
     * @param bool $replace whether a key that is already pinned may be replaced
     * @return string the fingerprint of the pinned key
     * @throws LocalizedException when the entry is a placeholder, a key is pinned and may not be replaced, or the
     *                            write fails
     */
    private function pin(string $key, bool $replace): string
    {
        if (str_starts_with($key, self::PLACEHOLDER_PREFIX)) {
            throw new LocalizedException(
                __('The chosen entry is the placeholder of a retired key, not a key the store hashed with.')
            );
        }
        $current = $this->pinnedHashKey->get();
        if ($current === $key) {
            return $this->fingerprint($key);
        }
        if ($current !== null && !$replace) {
            throw new LocalizedException(__(
                'Keyed hashes are already pinned to key %1. Replacing the pin changes every pinned hash; '
                . 'ask for the replacement explicitly to go on.',
                $this->fingerprint($current)
            ));
        }
        if (!$this->writer->checkIfWritable()) {
            throw new LocalizedException(
                __('app/etc/env.php and app/etc/config.php must both be writable; the store writes them together.')
            );
        }
        $this->writer->saveConfig([
            ConfigFilePool::APP_ENV => $this->nested(PinnedHashKeyInterface::CONFIG_PATH, $key),
        ]);
        if ($this->pinnedHashKey->get() !== $key) {
            throw new LocalizedException(__('The pinned key did not read back from the deployment configuration.'));
        }

        return $this->fingerprint($key);
    }

    /**
     * Build the nested configuration array that holds a value at a slash-separated path
     *
     * @param string $path the path
     * @param string $value the value
     * @return array<string, mixed> the nested array
     */
    private function nested(string $path, string $value): array
    {
        $data = $value;
        foreach (array_reverse(explode('/', $path)) as $segment) {
            $data = [$segment => $data];
        }

        return $data;
    }

    /**
     * Compute a key's fingerprint: the first 16 hexadecimal characters of the SHA-256 of its bytes
     *
     * @param string $key the key entry; an entry with the encoded-key prefix stands for the bytes it encodes
     * @return string the fingerprint
     */
    private function fingerprint(string $key): string
    {
        $bytes = str_starts_with($key, self::ENCODED_KEY_PREFIX)
            ? base64_decode(substr($key, strlen(self::ENCODED_KEY_PREFIX)), true)
            : $key;

        return substr(hash('sha256', $bytes === false ? $key : $bytes), 0, 16);
    }
}
