<?php
/**
 * Copyright (c) 2026. Volodymyr Hryvinskyi. All rights reserved.
 * Author: Volodymyr Hryvinskyi <volodymyr@hryvinskyi.com>
 * GitHub: https://github.com/hryvinskyi
 */

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyManager\Plugin;

use Hryvinskyi\EncryptionKeyManager\Api\DecryptLogSettingsInterface;
use Hryvinskyi\EncryptionKeyManager\Api\DeploymentKeysInterface;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Encryption\EncryptorInterface;
use Psr\Log\LoggerInterface;

/**
 * Logs where the store decrypts a value encrypted under a key older than the active one
 *
 * Between re-encrypting the stored values and retiring the old keys, every such line names code that still needs an
 * old key: a value the re-encryption did not reach, or one that lives outside the database. The line carries the
 * value's key index, the active index and the call stack without arguments, and an id derived from that stack so
 * that repeats can be counted. Neither the value nor what it decrypts to is ever logged.
 *
 * Off unless switched on. Logging never changes the decryption's result, and a failure to log is dropped.
 */
class LogOldKeyDecrypts
{
    private const KEY_INDEX = '/^(0|[1-9][0-9]*):[0-9]+:/';

    /**
     * @param DecryptLogSettingsInterface $settings whether to log
     * @param DeploymentKeysInterface $deploymentKeys the key ring, for the active index
     * @param DirectoryList $directoryList the store root, left out of the logged file paths
     * @param LoggerInterface $logger the decryption log
     */
    public function __construct(
        private readonly DecryptLogSettingsInterface $settings,
        private readonly DeploymentKeysInterface $deploymentKeys,
        private readonly DirectoryList $directoryList,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Log the call when the decrypted value was encrypted under an old key
     *
     * @param EncryptorInterface $subject the store's encryptor
     * @param mixed $result what the value decrypted to, returned untouched
     * @param mixed $data the stored value; only its key index is read
     * @return mixed the decryption's result
     */
    public function afterDecrypt(EncryptorInterface $subject, mixed $result, mixed $data): mixed
    {
        try {
            if (!is_string($data) || preg_match(self::KEY_INDEX, $data, $match) !== 1) {
                return $result;
            }
            $keyIndex = (int) $match[1];
            $activeIndex = count($this->deploymentKeys->ring()) - 1;
            // The switch is read last: it is usually absent, and a path the configuration does not hold makes the
            // store reload its whole deployment configuration, which no decryption under the active key should cost.
            if ($keyIndex >= $activeIndex || !$this->settings->isEnabled()) {
                return $result;
            }
            $frames = $this->frames();
            $this->logger->info('A value encrypted under an old key was decrypted', [
                'key_index' => $keyIndex,
                'active_index' => $activeIndex,
                'trace_id' => substr(hash('sha256', implode('|', $frames)), 0, 16),
                'trace' => implode(' | ', $frames),
            ]);
        } catch (\Throwable) {
            // A decryption log must never break the decryption it observes.
            return $result;
        }

        return $result;
    }

    /**
     * Describe the call stack, without arguments and without the store root in file paths
     *
     * @return list<string> one line per frame, innermost first
     */
    private function frames(): array
    {
        $root = rtrim($this->directoryList->getRoot(), '/') . '/';
        $frames = [];
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
            $file = isset($frame['file'])
                ? str_replace($root, '', $frame['file']) . ':' . ($frame['line'] ?? 0)
                : '[internal]';
            $frames[] = $file . ' ' . ($frame['class'] ?? '') . ($frame['type'] ?? '') . $frame['function'];
        }

        return $frames;
    }
}
